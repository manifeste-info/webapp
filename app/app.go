package app

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/manifeste-info/webapp/auth"
	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/events"
	"github.com/manifeste-info/webapp/mail"
	"github.com/manifeste-info/webapp/notifications"
	"github.com/manifeste-info/webapp/notifications/empty"
	"github.com/manifeste-info/webapp/notifications/slack"
	"github.com/manifeste-info/webapp/security"
	"github.com/manifeste-info/webapp/users"
	"github.com/manifeste-info/webapp/utils"
	"github.com/oklog/ulid"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	limiter "github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	memory "github.com/ulule/limiter/v3/drivers/store/memory"
)

// App is the core structure that is shared between all handlers
type App struct {
	Notifier         notifications.Notifier
	Environment      string
	JWTSecret        []byte
	ReportsThreshold int
}

// New returns a newly configured App
func New(c config.Config) (App, error) {
	var a App

	switch c.Notifier {
	case "", "empty":
		a.Notifier = empty.Empty{}
	case "slack":
		a.Notifier = slack.Slack{}
	default:
		return App{}, fmt.Errorf("notifier %s is not supported", c.Notifier)
	}

	a.Environment = c.Env

	a.JWTSecret = []byte(os.Getenv("JWT_SECRET"))
	if len(a.JWTSecret) == 0 {
		return App{}, fmt.Errorf("JWT_SECRET cannot be empty")
	}

	var err error
	a.ReportsThreshold, err = strconv.Atoi(c.ReportThreshold)
	if err != nil {
		return App{}, nil
	}
	return a, nil
}

func CreateRouter(a App) (*gin.Engine, error) {
	r := gin.Default()

	rate, err := limiter.NewRateFromFormatted("10-S")
	if err != nil {
		return r, err
	}

	// if under development, use basic auth on all routes
	if a.Environment != "release" {
		user, pass := os.Getenv("BASIC_AUTH_USER"), os.Getenv("BASIC_AUTH_PASS")
		if user == "" || pass == "" {
			return nil, fmt.Errorf("basic auth is misconfigured: user or pass can't be empty")
		}
		r.Use(gin.BasicAuth(
			gin.Accounts{
				user: pass,
			},
		))
	}

	store := memory.NewStore()
	rateLimiterMiddleware := mgin.NewMiddleware(limiter.New(store, rate))
	r.ForwardedByClientIP = true
	r.Use(rateLimiterMiddleware)

	r.NoRoute(notFoundPage)
	r.LoadHTMLGlob("layout/templates/*.html")
	r.GET("/", a.homePage)
	r.GET("/health", healthPage)
	r.GET("/security.txt", securityTxtPage)
	r.GET("/robots.txt", robotsTxtPage)
	r.GET("/mentions-legales", legalPage)
	r.GET("/apropos", aboutPage)
	r.GET("/recherche", searchPage)
	r.GET("/connexion", a.connectionPage)
	r.GET("/nouveaucompte", registrationPage)
	r.GET("/deconnexion", disconnectPage)
	r.GET("/evenement/:id", eventPage)
	r.GET("/signaler/:id", a.reportEventPage)

	r.POST("/connexion", a.connectionProcess)
	r.POST("/nouveaucompte", a.registrationProcess)

	authorized := r.Group("/moncompte")
	authorized.Use(authRequired(a))
	{
		// when a user connects successfully, the redirect is done using the intial
		// requst method, which is POST. So this route need to handle GET and POST
		authorized.GET("/", a.accountPage)
		authorized.POST("/", a.accountPage)

		authorized.GET("/nouveau", a.newPage)
		authorized.GET("/maj/:eventID", a.updatePage)
		authorized.GET("/supprimer/:eventID", a.deleteProcess)
		authorized.GET("/confirmation/:token", a.confirmationProcess)

		authorized.POST("/nouveau", a.newProcess)
		authorized.POST("/maj/:eventID", a.updateProcess)
	}

	admin := r.Group("/admin")
	admin.Use(authRequired(a), adminRequired(a))
	{
		admin.GET("/dashboard", adminDashboardPage)
		admin.GET("/utilisateurs", adminAllUsersPage)
		admin.GET("/evenements", adminAllEventsPage)

		admin.POST("/evenement", adminEventProcess)
		admin.POST("/utilisateur", adminUserProcess)
	}

	return r, nil
}

/*
	Not found page handler

	This handler is called when there is a 404 Not Found
*/
func notFoundPage(c *gin.Context) {
	c.HTML(http.StatusNotFound, "notfound.html", nil)
}

/*
	Health page handler

	This handler returns a JSON formated string with some content, just to show that
	the application is up & running
*/
func healthPage(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, gin.H{"status": "ok", "path": c.FullPath()})
}

/*
	Security.txt page handler

	This page returns the security.txt file
*/
func securityTxtPage(c *gin.Context) {
	page := `Contact: mailto:manifeste.info+security@eml.cc
Expires: 2024-05-01T13:37:00.000Z
Preferred-Languages: fr, en
Canonical: https://manifeste.info/security.txt`
	c.String(http.StatusOK, page)
}

/*
	Robots.txt page handler

	This handler returns the robots.txt file
*/
func robotsTxtPage(c *gin.Context) {
	page := `User-Agent: *
Disallow: /admin/`
	c.String(http.StatusOK, page)
}

/*
	Legal page handler

	This page returns the legal stuff needed
*/
func legalPage(c *gin.Context) {
	c.HTML(http.StatusOK, "legal.html", nil)
}

/*
	Home page handler

	This handler returns the home page of the webapp
*/
func (a App) homePage(c *gin.Context) {
	var err error
	type page struct {
		HasMessage   bool
		MessageTitle string
		Message      string
		Cities       []string
	}
	p := page{}

	if a.Environment != "release" {
		p.HasMessage = true
		p.MessageTitle = "???? Attention."
		p.Message = "Manifeste.info est actuellement en phase de d??veloppement, aucune donn??e ne sera persist??e."
	}

	// todo: better error handling
	// if the following fails, it is not critical. Should we display an error?
	// p.Cities, err = events.GetCitiesWithEvents()
	p.Cities, err = events.GetCitiesWithFutureEvents()
	if err != nil {
		log.Errorf("cannot get cities list: %s", err)
	}
	c.HTML(http.StatusOK, "home.html", p)
}

/*
	About page handler

	This handler returns the about page of the webapp
*/
func aboutPage(c *gin.Context) {
	c.HTML(http.StatusOK, "about.html", nil)
}

/*
	Search page handler

	This handler returns all the results that match the parameters given in URL
*/
func searchPage(c *gin.Context) {
	var err error
	type page struct {
		Success    bool
		ErrMsg     string
		HasResults bool
		City       string

		Events []events.Event
	}
	var p page

	city := strings.Title(c.Query("ville"))
	if city == "" {
		p.ErrMsg = "Aucune ville n'a ??t?? donn??e en param??tre."
		c.HTML(http.StatusNotFound, "search.html", p)
		return
	}

	// get all the events matching the city in the database
	p.Events, err = events.GetEventsByCityOrdered(city)
	if err != nil {
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "search.html", p)
		log.Errorf("cannot get all events for city '%ss': %s", city, err)
		return
	}

	if len(p.Events) != 0 {
		p.HasResults = true
	}

	p.City = city
	p.Success = true
	c.HTML(http.StatusOK, "search.html", p)
}

/*
	Connection page handler

	This handler returns the connection form
*/
func (a App) connectionPage(c *gin.Context) {
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success bool

		// in case of message, not used in this handler as it is primary if you are
		// already connected
		HasMsg bool
		Msg    string
	}
	var p page

	token, err := c.Cookie("token")
	if err == nil && token != "" {
		p.HasMsg, err = auth.VerifyJWT(token, a.JWTSecret)
		if err == nil {
			p.Msg = "Tu es d??j?? connect????e."
		}
	}

	c.HTML(http.StatusOK, "connection.html", p)
}

/*
	Connection process handler

	This handler receives the credentials and try to authenticate the user. If it
	succeed, it sets the session cookie
*/
func (a App) connectionProcess(c *gin.Context) {
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success bool

		// in case of message, not used in this handler as it is primary if you are
		// already connected
		HasMsg bool
		Msg    string
	}
	p := page{}

	email := c.PostForm("email")
	password := c.PostForm("password")

	jwt, err := auth.Authenticate(email, password, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Mauvais email/mot de passe."
		c.HTML(http.StatusInternalServerError, "connection.html", p)
		log.Errorf("cannot authenticate user '%s': %s", email, err)
		return
	}

	c.SetCookie("token", jwt.Token, jwt.Expires.Hour()*3600, "/", c.Request.URL.Hostname(), false, true)
	// p.Success = true
	// c.HTML(http.StatusOK, "connection.html", p)
	c.Redirect(http.StatusFound, "/moncompte")
}

/*
	Registration page handler

	This handler returns the registration form
*/
func registrationPage(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", nil)
}

/*
	Registration process handler

	This handler process the registration request, and returns the regsiter page
	if something is missing.
*/
func (a App) registrationProcess(c *gin.Context) {
	type page struct {
		// in case of error
		Error    bool
		ErrMsg   string
		Nickname string
		Email    string

		// in case of success
		Success bool
	}

	p := page{
		Nickname: c.PostForm("nickname"),
		Email:    c.PostForm("email"),
	}
	pass, passconfirm := c.PostForm("password"), c.PostForm("passwordRetype")

	// check that no field is empty
	if p.Nickname == "" || p.Email == "" || pass == "" || passconfirm == "" {
		p.Error = true
		p.ErrMsg = "Tous les champs marqu??s d'un ast??risque sont obligatoires."
		c.HTML(http.StatusOK, "register.html", p)
		return
	}

	// check that passwords are the same
	if pass != passconfirm {
		p.Error = true
		p.ErrMsg = "Les mots de passe ne correspondent pas."
		c.HTML(http.StatusOK, "register.html", p)
		return
	}

	// check if the password lenght matches the default value
	if len(pass) < config.MinPasswordLen {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Le mot de passe doit faire au minimum %d caract??res.", config.MinPasswordLen)
		c.HTML(http.StatusBadRequest, "register.html", p)
		return
	}

	// check that the email address isn't already in database
	isPresent, err := users.CheckIfExists(p.Email)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la cr??ation du compte."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Errorf("cannot check if account exists: %s", err)
		return
	}

	if isPresent {
		p.Error = true
		p.ErrMsg = "Un compte avec cette adresse email existe d??j??."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Errorf("account %s already in database", p.Email)
		return
	}

	// create the account validation token
	validToken := uuid.NewString()
	log.Infof("created validation token '%s' for user email '%s'", validToken, p.Email)

	id := utils.CreateULID()

	// create user account
	if err := users.CreateAccount(p.Nickname, p.Email, pass, validToken, id); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la cr??ation du compte."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Errorf("cannot create account: %s", err)
		return
	}

	// authenticate the user
	jwt, err := auth.Authenticate(p.Email, pass, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la cr??ation du compte."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Errorf("cannot authenticate user: %s", err)
		return
	}

	if err := mail.SendConfirmationToken(p.Email, jwt.Token, validToken); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de l'envoi du mail de confirmation."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Errorf("cannot send confirmation token: %s", err)
		return
	}

	payload := notifications.PayloadNewAccount{
		UserID:                 id,
		Email:                  p.Email,
		Nickname:               p.Nickname,
		AccountValidationToken: validToken,
	}

	if err := a.Notifier.SendNewAccount(payload); err != nil {
		log.Errorf("cannot send new account notification: %s", err)
	}

	c.SetCookie("token", jwt.Token, jwt.Expires.Hour()*3600, "/", c.Request.URL.Hostname(), false, true)
	p.Success = true
	c.HTML(http.StatusOK, "register.html", p)
	log.Printf("user %s created", p.Email)
}

/*
	Account page handler

	This handler returns the user account page. It needs to be authentified to
	access this page
*/
func (a App) accountPage(c *gin.Context) {
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of message to display
		HasMsg bool
		Msg    string

		Name                string
		UserID              string
		IsAdmin             bool
		HasEvents           bool
		HasConfirmedAccount bool
		Events              []events.Event
	}
	p := page{}

	// retrieve the session token
	token, err := c.Cookie("token")
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu aies ??t?? d??connect????e."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Errorf("cannot find session token: %s", err)
		return
	}

	// get claims infos based on the jwt
	cl, err := auth.GetJWTClaims(token, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la r??cup??ration de tes informations."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Errorf("cannot get user infos: %s", err)
		return
	}
	p.Name = strings.Title(cl.FirstName)

	// check if the user is admin or not
	p.IsAdmin, err = users.IsAdmin(cl.UID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la r??cup??ration de tes informations."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Errorf("cannot get user id: %s", err)
		return
	}

	// get events created by this user
	p.Events, err = events.GetEventsByUserID(cl.UID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la r??cup??ration de tes ??v??nements."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Errorf("cannot get user events: %s", err)
		return
	}

	if len(p.Events) != 0 {
		p.HasEvents = true
	}

	p.HasConfirmedAccount, err = users.HasConfirmedAccount(cl.UID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la r??cup??ration de tes informations."
		c.HTML(http.StatusInternalServerError, "account.html", p)
		log.Errorf("cannot get user accout confirmation: %s", err)
		return
	}

	c.HTML(http.StatusOK, "account.html", p)
}

/*
	Disconnect page handler

	This handler disconnects a user by deleting its session token from the k/v
	store
*/
func disconnectPage(c *gin.Context) {
	type page struct {
		Success bool
		Msg     string
	}
	var p page

	_, err := c.Cookie("token")
	if err != nil {
		p.Msg = "Tu n'es pas connect????e."
		c.HTML(http.StatusUnauthorized, "disconnect.html", p)
		log.Errorf("cannot get user cookie: %s", err)
		return
	}

	c.SetCookie("token", "", 1, "/", c.Request.URL.Hostname(), false, true)
	p.Success = true
	c.HTML(http.StatusOK, "disconnect.html", p)
}

/*
	New page handler

	This handler serves the form to create a new event.
*/
func (a App) newPage(c *gin.Context) {
	var err error
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success bool

		HasConfirmedAccount bool

		Cities     []string
		Categories []string

		City        string `form:"city"`
		Address     string `form:"address"`
		Description string `form:"description"`
		Date        string `form:"date"`
		Time        string `form:"time"`
		Organizer   string `form:"organizer"`
		Link        string `form:"link"`
		Category    string `form:"category"`
	}
	var p page

	token, err := c.Cookie("token")
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois d??connect????e."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Errorf("cannot get user cookie: %s", err)
		return
	}

	cl, err := auth.GetJWTClaims(token, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Errorf("cannot get user id: %s", err)
		return
	}

	p.HasConfirmedAccount, err = users.HasConfirmedAccount(cl.UID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Errorf("cannot check if user has confirmed its account: %s", err)
		return
	}

	p.Cities = utils.AllCities
	p.Categories = events.GetAllCategories()
	p.Category = events.GetAllCategories()[0]
	c.HTML(http.StatusOK, "new.html", p)
}

/*
	New process handler

	This handler checks if the new event form has been done correclty, and if yes
	it creates the new event in the database
*/
func (a App) newProcess(c *gin.Context) {
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success bool

		HasConfirmedAccount bool

		City        string `form:"city"`
		Address     string `form:"address"`
		Description string `form:"description"`
		Date        string `form:"date"`
		Time        string `form:"time"`
		Organizer   string `form:"organizer"`
		Link        string `form:"link"`
		Category    string `form:"category"`

		Cities     []string
		Categories []string
	}
	var p page

	if err := c.ShouldBind(&p); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la r??cup??ration des informations."
		c.HTML(http.StatusBadRequest, "new.html", p)
		log.Errorf("cannot get event informations from new form: %s", err)
		return
	}

	if p.City == "" || p.Address == "" || p.Description == "" || p.Date == "" || p.Time == "" || p.Organizer == "" || p.Category == "" {
		p.Error = true
		p.ErrMsg = "Tous les champs marqu??s d'un ast??rique sont obligatoires."
		c.HTML(http.StatusOK, "new.html", p)
		return
	}

	// get the user ID
	token, err := c.Cookie("token")
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois d??connect????e."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Errorf("cannot get user cookie: %s", err)
		return
	}

	cl, err := auth.GetJWTClaims(token, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "new.html", p)
		log.Errorf("cannot get user id: %s", err)
		return
	}

	p.HasConfirmedAccount, err = users.HasConfirmedAccount(cl.UID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Errorf("cannot check if user hsa confirmed its account: %s", err)
		return
	}

	var eid string
	if p.HasConfirmedAccount {
		city := p.City
		if !utils.StringInSlice(p.City, utils.AllCities) {
			city = utils.GetClosestCityName(p.City)
		}

		// create the event in the database
		eid, err = events.Create(city, p.Address, p.Date, p.Time, p.Description, p.Organizer, p.Link, cl.UID, p.Category)
		if err != nil {
			p.Error = true
			p.ErrMsg = "Une erreur est survenue, impossible de cr??er l'??v??nement."
			c.HTML(http.StatusInternalServerError, "new.html", p)
			log.Errorf("cannot create event id: %s", err)
			return
		}
		p.Success = true
	}

	payload := notifications.PayloadNewEvent{
		EventID:       eid,
		UserID:        cl.UID,
		EventDesc:     p.Description,
		EventCategory: p.Category,
		Kind:          notifications.KindCreate,
	}
	if err := a.Notifier.SendNewEvent(payload); err != nil {
		log.Errorf("cannot send create payload via notifier: %s", err)
	}
	p.Cities = utils.AllCities
	p.Categories = utils.RemoveFromSliceOrdered(events.GetAllCategories(), p.Category)
	c.HTML(http.StatusOK, "new.html", p)
}

/*
	Event page handler

	This handlers returns a single event, idenfied by its event ID provided in the
	URL
*/
func eventPage(c *gin.Context) {
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		Event events.Event
	}
	var p page

	id := c.Param("id")
	e, err := events.GetEventByID(id, true)
	if err != nil {
		p.Error = true
		if err.Error() == config.ErrEventDoesNotExist {
			p.ErrMsg = "Cet ??v??nement n'existe pas ou plus."
			c.HTML(http.StatusNotFound, "event.html", p)
			log.Errorf("event with ID '%s' does not exist (anymore)", id)
			return
		}
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusNotFound, "event.html", p)
		log.Errorf("event with ID '%s' can't be found: %s", id, err)
		return
	}
	p.Event = e

	c.HTML(http.StatusOK, "event.html", p)
}

/*
	Update page handler

	This handler show an update form, which is basically the same as the creation
	form, but with pre-populated fields
*/
func (a App) updatePage(c *gin.Context) {
	var err error
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success bool

		Exists bool

		Event      events.Event
		Categories []string
	}
	var p page

	id := c.Param("eventID")
	if id == "" {
		p.Error = true
		p.ErrMsg = "L'ID de l'??v??nement ne peut pas ??tre vide."
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Error("empty id")
		return
	}

	p.Event, err = events.GetEventByID(id, false)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la r??cup??ration de l'??v??nement."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Errorf("cannot get event: %s", err)
		return
	}

	// get the user ID
	token, err := c.Cookie("token")
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois d??connect????e."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Errorf("cannot get user cookie: %s", err)
		return
	}

	cl, err := auth.GetJWTClaims(token, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Errorf("cannot get user id: %s", err)
		return
	}

	if p.Event.CreatedBy != cl.UID {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu n'aies pas cr???? cet ??v??nement."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Errorf("user tries to update a event not created by him/her: uid: %s, eventID: %s, event created by: %s",
			cl.UID, p.Event.ID, p.Event.CreatedBy)
		return
	}

	// the format received from DB is 2022-04-28 13:00:00 +0000 UTC 08:00
	parts := strings.Split(p.Event.Date, " ")
	// rebuild the date
	dateParts := strings.Split(parts[0], "-")
	p.Event.Date = fmt.Sprintf("%s/%s/%s", dateParts[2], dateParts[1], dateParts[0])
	// rebuild the time
	timeParts := strings.Split(parts[1], ":")
	p.Event.Time = fmt.Sprintf("%s:%s", timeParts[0], timeParts[1])

	p.Categories = utils.RemoveFromSliceOrdered(events.GetAllCategories(), p.Event.Category)
	c.HTML(http.StatusOK, "update.html", p)
}

/*
	Update process handler

	This handler receives an event from the update form a updates the
	corresponding event in the database
*/
func (a App) updateProcess(c *gin.Context) {
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success bool

		City        string `form:"city"`
		Address     string `form:"address"`
		Description string `form:"description"`
		Date        string `form:"date"`
		Time        string `form:"time"`
		Organizer   string `form:"organizer"`
		Link        string `form:"link"`
		ID          string
		Category    string `form:"category"`
	}
	var p page

	p.ID = c.Param("eventID")
	if p.ID == "" {
		p.Error = true
		p.ErrMsg = "L'ID de l'??v??nement ne peut pas ??tre vide."
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Error("empty id")
		return
	}

	if err := c.ShouldBind(&p); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la r??cup??ration des informations."
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Errorf("cannot get event informations from update form: %s", err)
		return
	}

	if p.City == "" || p.Address == "" || p.Description == "" || p.Date == "" || p.Time == "" || p.Organizer == "" {
		p.Error = true
		p.ErrMsg = "Tous les champs marqu??s d'un ast??rique sont obligatoires."
		c.HTML(http.StatusOK, "update.html", p)
		return
	}

	e := events.Event{
		City:        p.City,
		Address:     p.Address,
		Date:        p.Date,
		Time:        p.Time,
		Description: p.Description,
		Organizer:   p.Organizer,
		Link:        p.Link,
		ID:          p.ID,
		Category:    p.Category,
	}

	// get the user ID
	token, err := c.Cookie("token")
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois d??connect????e."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Errorf("cannot get user cookie: %s", err)
		return
	}

	cl, err := auth.GetJWTClaims(token, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Errorf("cannot get user id: %s", err)
		return
	}

	createdBy, err := events.GetEventCreatorID(p.ID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Errorf("cannot get created_by id: %s", err)
		return
	}

	isAdmin, err := users.IsAdmin(cl.UID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Errorf("cannot check if user is admin: %s", err)
		return
	}

	if createdBy != cl.UID && !isAdmin {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu n'aies pas cr???? cet ??v??nement."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Errorf("user tries to update a event not created by him/her: uid: %s, eventID: %s, event created by: %s",
			cl.UID, p.ID, createdBy)
		return
	}
	// if we end up here, it means that the user doing the request is not the
	// event author, but is an admin, so we continue

	if err := events.Update(p.ID, e); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la mise ?? jour de l'??v??nement"
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Errorf("cannot get event informations from update form: %s", err)
		return
	}

	payload := notifications.PayloadNewEvent{
		EventID:       p.ID,
		UserID:        cl.UID,
		EventDesc:     p.Description,
		EventCategory: p.Category,
		Kind:          notifications.KindEdit,
	}
	if err := a.Notifier.SendNewEvent(payload); err != nil {
		log.Errorf("cannot send edit payload via notifier: %s", err)
	}

	p.Success = true
	c.HTML(http.StatusOK, "update.html", p)
}

/*
	Delete process handler

	This handler receives an event ID and removes it from the DB
*/
func (a App) deleteProcess(c *gin.Context) {
	type page struct {
		Success bool
	}
	p := page{
		Success: false,
	}
	// get event ID
	eventID := c.Param("eventID")
	if eventID == "" {
		c.HTML(http.StatusBadRequest, "delete.html", p)
		return
	}

	// get user ID
	token, err := c.Cookie("token")
	if err != nil {
		c.HTML(http.StatusUnauthorized, "delete.html", p)
		log.Errorf("cannot get user cookie: %s", err)
		return
	}

	cl, err := auth.GetJWTClaims(token, a.JWTSecret)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "delete.html", p)
		log.Errorf("cannot get user id: %s", err)
		return
	}

	// get the list of events created by this user
	el, err := events.GetEventsByUserID(cl.UID)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "delete.html", p)
		log.Errorf("cannot get user events: %s", err)
		return
	}

	var createdByUser bool
	for _, e := range el {
		if e.ID == eventID {
			createdByUser = true
			break
		}
	}

	if !createdByUser {
		c.HTML(http.StatusUnauthorized, "delete.html", p)
		log.Error("user trying to delete event created by another one")
		return
	}

	// delete event by event ID
	if err := events.Delete(eventID); err != nil {
		log.Errorf("cannot delete event '%s': %s", eventID, err)
		c.HTML(http.StatusInternalServerError, "delete.html", p)
		return
	}

	p.Success = true
	c.HTML(http.StatusOK, "delete.html", p)
}

/*
	Admin dashboard page handler

	This handler returns the admin dashboard, accessible only of the adminRequired
	middleware is successful
*/
func adminDashboardPage(c *gin.Context) {
	var err error
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success    bool
		SuccessMsg string

		IsAdmin          bool
		Event            events.Event
		NumOfEvents      int
		NumOfUsers       int
		NumOfBannedUsers int
	}
	p := page{
		IsAdmin: true,
	}

	p.NumOfEvents, err = events.GetNumOfEvents()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of events: %s", err)
		return
	}

	p.NumOfUsers, err = users.GetNumOfUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of users: %s", err)
		return
	}

	p.NumOfBannedUsers, err = users.GetNumOfBannedUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of banned users: %s", err)
		return
	}

	c.HTML(http.StatusOK, "admin.html", p)
}

/*
	Admin event process handler

	This handler receives an event ID with an instruction: either 'supprimer'
	which will delete the event, or 'modifier' which will allow an admin to edit
	the event
*/
func adminEventProcess(c *gin.Context) {
	var err error
	action := c.PostForm("action")
	eventID := c.PostForm("eventID")

	log.Printf("admin: action: %s, event ID: %s", action, eventID)

	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success    bool
		SuccessMsg string

		IsAdmin          bool
		Event            events.Event
		NumOfEvents      int
		NumOfUsers       int
		NumOfBannedUsers int
	}
	p := page{
		IsAdmin: true,
	}

	p.NumOfEvents, err = events.GetNumOfEvents()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of events: %s", err)
		return
	}

	p.NumOfUsers, err = users.GetNumOfUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of users: %s", err)
		return
	}

	p.NumOfBannedUsers, err = users.GetNumOfBannedUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of banned users: %s", err)
		return
	}

	if eventID == "" {
		p.Error = true
		p.ErrMsg = "L'event ID est vide."
		c.HTML(http.StatusBadRequest, "admin.html", p)
		return
	}

	switch action {
	case "delete":
		if err = events.Delete(eventID); err != nil {
			p.Error = true
			p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
			c.HTML(http.StatusInternalServerError, "admin.html", p)
			log.Errorf("admin: cannot delete event '%s': %s", eventID, err)
			return
		}

		p.Success = true
		p.SuccessMsg = "L'??v??nement a ??t?? supprim?? avec succ??s."
		log.Printf("admin: deleted eventID '%s'", eventID)
		c.HTML(http.StatusOK, "admin.html", p)
	case "edit":
		p.Event, err = events.GetEventByID(eventID, false)
		if err != nil {
			p.Error = true
			p.ErrMsg = fmt.Sprintf("Une erreur est survenue lors de la r??cup??ration de l'??v??nement: %s", err)
			c.HTML(http.StatusInternalServerError, "admin.html", p)
			log.Errorf("admin: cannot get event with id '%s': %s", eventID, err)
			return
		}

		// the format received from DB is 2022-04-28 13:00:00 +0000 UTC 08:00
		parts := strings.Split(p.Event.Date, " ")
		// rebuild the date
		dateParts := strings.Split(parts[0], "-")
		p.Event.Date = fmt.Sprintf("%s/%s/%s", dateParts[2], dateParts[1], dateParts[0])
		// rebuild the time
		timeParts := strings.Split(parts[1], ":")
		p.Event.Time = fmt.Sprintf("%s:%s", timeParts[0], timeParts[1])

		log.Printf("admin: updating eventID '%s'", eventID)
		c.HTML(http.StatusOK, "update.html", p)
	}
}

/*
	Admin user process handler

	This handler allows admins to ban users based on their user ID by replacing
	their hashed password in the database by the string 'banned', which will
	prevent them to log in, but will keep their email in the database preventing
	them to create another accounts
*/
func adminUserProcess(c *gin.Context) {
	var err error

	userID := c.PostForm("userID")
	action := c.PostForm("action")

	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success    bool
		SuccessMsg string

		IsAdmin          bool
		Event            events.Event
		NumOfEvents      int
		NumOfUsers       int
		NumOfBannedUsers int
	}
	p := page{
		IsAdmin: true,
	}

	p.NumOfEvents, err = events.GetNumOfEvents()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of events: %s", err)
		return
	}

	p.NumOfUsers, err = users.GetNumOfUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of users: %s", err)
		return
	}

	p.NumOfBannedUsers, err = users.GetNumOfBannedUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Errorf("admin: cannot get tot num of banned users: %s", err)
		return
	}

	if userID == "" {
		p.Error = true
		p.ErrMsg = "L'user ID est vide."
		c.HTML(http.StatusBadRequest, "admin.html", p)
		return
	}

	switch action {
	case "ban":
		log.Printf("admin: banning userID: %s", userID)
		if err := users.Ban(userID); err != nil {
			p.Error = true
			p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
			c.HTML(http.StatusInternalServerError, "admin.html", p)
			log.Errorf("admin: cannot ban userID '%s': %s", userID, err)
			return
		}

		p.Success = true
		p.SuccessMsg = "L'utilisateur??rice a ??t?? banni."
		log.Printf("admin: banned userID '%s'", userID)
		c.HTML(http.StatusOK, "admin.html", p)
	case "validate":
		log.Printf("admin: validating userID: %s", userID)
		if err := users.ValidateAccount(userID); err != nil {
			p.Error = true
			p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
			c.HTML(http.StatusInternalServerError, "admin.html", p)
			log.Errorf("admin: cannot validate userID '%s': %s", userID, err)
			return
		}

		p.Success = true
		p.SuccessMsg = "L'utilisateur??rice a ??t?? valid??."
		log.Printf("admin: validated userID '%s'", userID)
		c.HTML(http.StatusOK, "admin.html", p)
	}
}

/*
	Confirmation process handler

	This handler checks if a confirmation token received by email is valid or not
*/
func (a App) confirmationProcess(c *gin.Context) {
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of message to display
		HasMsg bool
		Msg    string

		Name                string
		UserID              string
		IsAdmin             bool
		HasEvents           bool
		HasConfirmedAccount bool
		Events              []events.Event
	}
	p := page{}

	token, err := c.Cookie("token")
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu aies ??t?? d??connect????e."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		return
	}

	cl, err := auth.GetJWTClaims(token, a.JWTSecret)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "account.html", p)
		log.Errorf("cannot retrieve user ID: %s", err)
		return
	}
	p.Name = cl.FirstName

	accountToken := c.Param("token")
	isValid, err := mail.ValidateConfirmationToken(cl.UID, accountToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "account.html", p)
		return
	}

	if !isValid {
		p.Error = true
		p.ErrMsg = "Le token est invalide."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		return
	}

	if err := users.ValidateAccount(cl.UID); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "account.html", p)
		log.Errorf("cannot validate user account with ID '%s': %s", cl.UID, err)
		return
	}

	p.HasConfirmedAccount = true
	p.HasMsg = true
	p.Msg = "Ton adresse email a ??t?? valid??e ! Tu peux dor??navant publier des ??v??nements."
	c.HTML(http.StatusOK, "account.html", p)
}

/*
	All users page

	This page displays in a JSON format the list of all the users registered on
	the platform
*/
func adminAllUsersPage(c *gin.Context) {
	us, err := users.GetAllUsers()
	if err != nil {
		c.String(http.StatusInternalServerError, "an error occured: "+err.Error())
		return
	}

	for _, u := range us {
		c.IndentedJSON(http.StatusOK, gin.H{
			"user_id":                  u.ID,
			"nick_name":                u.Nickname,
			"email":                    u.Email,
			"account_validation_token": u.AccountValidationToken,
			"has_confirmed_account":    u.HasConfirmedAccount,
			"is_admin":                 u.IsAdmin,
			"created_at":               u.CreatedAt,
		})
	}
}

/*
	All events page

	This page displays in a JSON format the list of all the events created on
	the platform
*/
func adminAllEventsPage(c *gin.Context) {
	es, err := events.GetAllEvents()
	if err != nil {
		c.String(http.StatusInternalServerError, "an error occured: "+err.Error())
		return
	}

	for _, e := range es {
		c.IndentedJSON(http.StatusOK, gin.H{
			"event_id":    e.ID,
			"city":        e.City,
			"address":     e.Address,
			"date":        e.Date,
			"description": e.Description,
			"organizer":   e.Organizer,
			"link":        e.Link,
			"created_by":  e.CreatedBy,
		})
	}
}

/*
	Report event page
*/
func (a App) reportEventPage(c *gin.Context) {
	type page struct {
		Message string
	}
	p := page{
		Message: "Merci pour le signalement, nous l'??tudierons dans les plus brefs d??lais!",
	}

	id := c.Param("id")

	_, err := ulid.Parse(id)
	if err != nil {
		p.Message = "Erreur, l'ID de l'??v??nement est invalide."
		c.HTML(http.StatusBadRequest, "report.html", p)
		return
	}

	if err := security.ReportEvent(c.ClientIP(), id); err != nil {
		p.Message = err.Error()
		c.HTML(http.StatusTooManyRequests, "report.html", p)
		return
	}

	// get the number of reports of this event
	num, err := events.GetEventReports(id)
	if err != nil {
		log.Error("cannot get event id '%s' reports: %s", id, err)
		p.Message = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "report.html", p)
		return
	}

	log.Infof("event with id '%s' has %d reports", id, num)
	if num >= a.ReportsThreshold {
		payload := notifications.PayloadNewReport{
			EventID: id,
		}

		a.Notifier.SendNewReport(payload)
	}
	if err := events.UpdateEventReports(id, num+1); err != nil {
		logrus.Errorf("cannot update event reports for event '%s': %s", id, err)
	}

	c.HTML(http.StatusOK, "report.html", p)
}
