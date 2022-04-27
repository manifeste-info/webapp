package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/manifeste-info/webapp/auth"
	"github.com/manifeste-info/webapp/config"
	"github.com/manifeste-info/webapp/events"
	"github.com/manifeste-info/webapp/mail"
	"github.com/manifeste-info/webapp/users"

	limiter "github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	memory "github.com/ulule/limiter/v3/drivers/store/memory"
)

func CreateRouter() (*gin.Engine, error) {
	r := gin.Default()

	rate, err := limiter.NewRateFromFormatted("10-S")
	if err != nil {
		return r, err
	}

	store := memory.NewStore()
	rateLimiterMiddleware := mgin.NewMiddleware(limiter.New(store, rate))
	r.ForwardedByClientIP = true
	r.Use(rateLimiterMiddleware)

	r.LoadHTMLGlob("layout/templates/*.html")
	r.GET("/", homePage)
	r.GET("/health", healthPage)
	r.GET("/security.txt", securityTxtPage)
	r.GET("/robots.txt", robotsTxtPage)
	r.GET("/apropos", aboutPage)
	r.GET("/recherche", searchPage)
	r.GET("/connexion", connectionPage)
	r.GET("/nouveaucompte", registrationPage)
	r.GET("/deconnexion", disconnectPage)
	r.GET("/evenement/:id", eventPage)

	r.POST("/connexion", connectionProcess)
	r.POST("/nouveaucompte", registrationProcess)

	authorized := r.Group("/moncompte")
	authorized.Use(authRequired())
	{
		// when a user connects successfully, the redirect is done using the intial
		// requst method, which is POST. So this route need to handle GET and POST
		authorized.GET("/", accountPage)
		authorized.POST("/", accountPage)

		authorized.GET("/nouveau", newPage)
		authorized.GET("/maj/:eventID", updatePage)
		authorized.GET("/supprimer/:eventID", deleteProcess)
		authorized.GET("/confirmation/:token", confirmationProcess)

		authorized.POST("/nouveau", newProcess)
		authorized.POST("/maj/:eventID", updateProcess)
	}

	admin := r.Group("/admin")
	admin.Use(adminRequired())
	{
		admin.GET("/dashboard", adminDashboardPage)

		admin.POST("/evenement", adminEventProcess)
		admin.POST("/utilisateur", adminUserProcess)
	}

	return r, nil
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
	page := `Contact: mailto:security@manifeste.info
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
	Home page handler

	This handler returns the home page of the webapp
*/
func homePage(c *gin.Context) {
	var err error
	type page struct {
		Cities []string
	}
	p := page{}

	// todo: better error handling
	// if the following fails, it is not critical. Should we display an error?
	p.Cities, err = events.GetCitiesWithEvents()
	if err != nil {
		log.Printf("error: cannot get cities list: %s\n", err)
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

	city := c.Query("ville")
	if city == "" {
		p.ErrMsg = "Aucune ville n'a été donnée en paramètre."
		c.HTML(http.StatusNotFound, "search.html", p)
		return
	}

	// get all the events matching the city in the database
	p.Events, err = events.GetEventsByCityOrdered(city)
	if err != nil {
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "search.html", p)
		log.Printf("error: cannot get all events for city '%ss': %s", city, err)
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
func connectionPage(c *gin.Context) {
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

	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		log.Printf("error: cannot get user cookie: %s\n", err)
	}

	if sessionToken != "" {
		p.HasMsg = auth.IsAuthenticated(sessionToken)
		p.Msg = "Tu es déjà connecté·e."
	}
	c.HTML(http.StatusOK, "connection.html", p)
}

/*
	Connection process handler

	This handler receives the credentials and try to authenticate the user. If it
	succeed, it sets the session cookie
*/
func connectionProcess(c *gin.Context) {
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

	sessionToken, err := auth.Authenticate(email, password)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Mauvais email/mot de passe."
		c.HTML(http.StatusInternalServerError, "connection.html", p)
		return
	}

	c.SetCookie(config.SessionCookieName, sessionToken, config.SessionCookieExpiry, "/", c.Request.URL.Hostname(), false, true)
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
func registrationProcess(c *gin.Context) {
	type page struct {
		// in case of error
		Error     bool
		ErrMsg    string
		FirstName string
		LastName  string
		Email     string

		// in case of success
		Success bool
	}

	p := page{
		FirstName: c.PostForm("firstname"),
		LastName:  c.PostForm("lastname"),
		Email:     c.PostForm("email"),
	}
	pass, passconfirm := c.PostForm("password"), c.PostForm("passwordRetype")

	// check that no field is empty
	if p.FirstName == "" || p.LastName == "" || p.Email == "" || pass == "" || passconfirm == "" {
		p.Error = true
		p.ErrMsg = "Tous les champs marqués d'un astérisque sont obligatoires."
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
		p.ErrMsg = fmt.Sprintf("Le mot de passe doit faire au minimum %d caractères.", config.MinPasswordLen)
		c.HTML(http.StatusBadRequest, "register.html", p)
		return
	}

	// check that the email address isn't already in database
	isPresent, err := users.CheckIfExists(p.Email)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la création du compte."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Printf("error: cannot check if account exists: %s\n", err)
		return
	}

	if isPresent {
		p.Error = true
		p.ErrMsg = "Un compte avec cette adresse email existe déjà."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Printf("error: account %s already in database\n", p.Email)
		return
	}

	// create user account
	if err := users.CreateAccount(p.FirstName, p.LastName, p.Email, pass); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la création du compte."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Printf("error: cannot create account: %s\n", err)
		return
	}

	// authenticate the user
	sessionToken, err := auth.Authenticate(p.Email, pass)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la création du compte."
		c.HTML(http.StatusUnauthorized, "register.html", p)
		log.Printf("error: cannot authenticate user: %s\n", err)
		return
	}

	if err := mail.SendConfirmationToken(p.Email, sessionToken); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de l'envoi du mail de confirmation."
		c.HTML(http.StatusInternalServerError, "register.html", p)
		log.Printf("error: cannot send confirmation token: %s\n", err)
		return
	}

	c.SetCookie(config.SessionCookieName, sessionToken, config.SessionCookieExpiry, "/", c.Request.URL.Hostname(), false, true)
	p.Success = true
	c.HTML(http.StatusOK, "register.html", p)
	log.Printf("user %s created\n", p.Email)
}

/*
	Account page handler

	This handler returns the user account page. It needs to be authentified to
	access this page
*/
func accountPage(c *gin.Context) {
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
	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu aies été déconnecté·e."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Printf("error: cannot find session token: %s\n", err)
		return
	}

	// get user infos based on the cookie
	p.Name, _, _, err = users.GetUserInfos(sessionToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération de tes informations."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Printf("error: cannot get user infos: %s\n", err)
		return
	}
	p.Name = strings.Title(p.Name)

	// get user id to list all its events
	p.UserID, err = users.GetUserID(sessionToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération de tes informations."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Printf("error: cannot get user id: %s\n", err)
		return
	}

	// check if the user is admin or not
	p.IsAdmin, err = users.IsAdmin(p.UserID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération de tes informations."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Printf("error: cannot get user id: %s\n", err)
		return
	}

	// get events created by this user
	p.Events, err = events.GetEventsByUserID(p.UserID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération de tes évènements."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		log.Printf("error: cannot get user events: %s\n", err)
		return
	}

	if len(p.Events) != 0 {
		p.HasEvents = true
	}

	p.HasConfirmedAccount, err = users.HasConfirmedAccount(p.UserID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération de tes informations."
		c.HTML(http.StatusInternalServerError, "account.html", p)
		log.Printf("error: cannot get user accout confirmation: %s\n", err)
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
	}
	var p page

	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Success = false
		c.HTML(http.StatusUnauthorized, "disconnect.html", p)
		log.Printf("error: cannot get user cookie: %s\n", err)
		return
	}

	if ok := auth.Disconnect(sessionToken); !ok {
		p.Success = false
		c.HTML(http.StatusInternalServerError, "disconnect.html", p)
		log.Printf("error: cannot delete user cookie: %s\n", err)
		return
	}
	p.Success = true
	c.HTML(http.StatusOK, "disconnect.html", p)
}

/*
	New page handler

	This handler serves the form to create a new event.
*/
func newPage(c *gin.Context) {
	var err error
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
	}
	var p page

	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois déconnecté·e."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Printf("error: cannot get user cookie: %s\n", err)
		return
	}

	uid, err := users.GetUserID(sessionToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Printf("error: cannot get user id: %s\n", err)
		return
	}

	p.HasConfirmedAccount, err = users.HasConfirmedAccount(uid)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Printf("error: cannot check if user hsa confirmed its account: %s\n", err)
		return
	}

	c.HTML(http.StatusOK, "new.html", p)
}

/*
	New process handler

	This handler checks if the new event form has been done correclty, and if yes
	it creates the new event in the database
*/
func newProcess(c *gin.Context) {
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
	}
	var p page

	if err := c.ShouldBind(&p); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération des informations."
		c.HTML(http.StatusBadRequest, "new.html", p)
		log.Printf("error: cannot get event informations from new form: %s\n", err)
		return
	}

	if p.City == "" || p.Address == "" || p.Description == "" || p.Date == "" || p.Time == "" || p.Organizer == "" {
		p.Error = true
		p.ErrMsg = "Tous les champs marqués d'un astérique sont obligatoires."
		c.HTML(http.StatusOK, "new.html", p)
		return
	}

	// get the user ID
	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois déconnecté·e."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Printf("error: cannot get user cookie: %s\n", err)
		return
	}

	id, err := users.GetUserID(sessionToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "new.html", p)
		log.Printf("error: cannot get user id: %s\n", err)
		return
	}

	p.HasConfirmedAccount, err = users.HasConfirmedAccount(id)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusUnauthorized, "new.html", p)
		log.Printf("error: cannot check if user hsa confirmed its account: %s\n", err)
		return
	}

	if p.HasConfirmedAccount {
		// create the event in the database
		if err := events.Create(p.City, p.Address, p.Date, p.Time, p.Description, p.Organizer, p.Link, id); err != nil {
			p.Error = true
			p.ErrMsg = "Une erreur est survenue, impossible de créer l'évènement."
			c.HTML(http.StatusInternalServerError, "new.html", p)
			log.Printf("error: cannot create event id: %s\n", err)
			return
		}
		p.Success = true
	}

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
			p.ErrMsg = "Cet évènement n'existe pas ou plus."
			c.HTML(http.StatusNotFound, "event.html", p)
			log.Printf("error: event with ID '%s' does not exist (anymore)\n", id)
			return
		}
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusNotFound, "event.html", p)
		log.Printf("error: event with ID '%s' can't be found: %s\n", id, err)
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
func updatePage(c *gin.Context) {
	var err error
	type page struct {
		// in case of error
		Error  bool
		ErrMsg string

		// in case of success
		Success bool

		Exists bool
		Event  events.Event
	}
	var p page

	id := c.Param("eventID")
	if id == "" {
		p.Error = true
		p.ErrMsg = "L'ID de l'évènement ne peut pas être vide."
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Println("error: empty id")
		return
	}

	p.Event, err = events.GetEventByID(id, false)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération de l'évènement."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Printf("error: cannot get event: %s\n", err)
		return
	}

	// get the user ID
	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois déconnecté·e."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Printf("error: cannot get user cookie: %s\n", err)
		return
	}

	uid, err := users.GetUserID(sessionToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Printf("error: cannot get user id: %s\n", err)
		return
	}

	if p.Event.CreatedBy != uid {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu n'aies pas créé cet évènement."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Printf("error: user tries to update a event not created by him/her: uid: %s, eventID: %s, event created by: %s\n",
			uid, p.Event.ID, p.Event.CreatedBy)
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

	c.HTML(http.StatusOK, "update.html", p)
}

/*
	Update process handler

	This handler receives an event from the update form a updates the
	corresponding event in the database
*/
func updateProcess(c *gin.Context) {
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
	}
	var p page

	p.ID = c.Param("eventID")
	if p.ID == "" {
		p.Error = true
		p.ErrMsg = "L'ID de l'évènement ne peut pas être vide."
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Println("error: empty id")
		return
	}

	if err := c.ShouldBind(&p); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la récupération des informations."
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Printf("error: cannot get event informations from update form: %s\n", err)
		return
	}

	if p.City == "" || p.Address == "" || p.Description == "" || p.Date == "" || p.Time == "" || p.Organizer == "" {
		p.Error = true
		p.ErrMsg = "Tous les champs marqués d'un astérique sont obligatoires."
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
	}

	// get the user ID
	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu sois déconnecté·e."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Printf("error: cannot get user cookie: %s\n", err)
		return
	}

	uid, err := users.GetUserID(sessionToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Printf("error: cannot get user id: %s\n", err)
		return
	}

	createdBy, err := events.GetEventCreatorID(p.ID)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Printf("error: cannot get created_by id: %s\n", err)
		return
	}

	isAdmin, err := users.IsAdmin(uid)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "update.html", p)
		log.Printf("error: cannot check if user is admin: %s\n", err)
		return
	}

	if createdBy != uid && !isAdmin {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu n'aies pas créé cet évènement."
		c.HTML(http.StatusUnauthorized, "update.html", p)
		log.Printf("error: user tries to update a event not created by him/her: uid: %s, eventID: %s, event created by: %s\n",
			uid, p.ID, createdBy)
		return
	}
	// if we end up here, it means that the user doing the request is not the
	// event author, but is an admin, so we continue

	if err := events.Update(p.ID, e); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue lors de la mise à jour de l'évènement"
		c.HTML(http.StatusBadRequest, "update.html", p)
		log.Printf("error: cannot get event informations from update form: %s\n", err)
		return
	}

	p.Success = true
	c.HTML(http.StatusOK, "update.html", p)
}

/*
	Delete process handler

	This handler receives an event ID and removes it from the DB
*/
func deleteProcess(c *gin.Context) {
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
	cookie, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		c.HTML(http.StatusUnauthorized, "delete.html", p)
		log.Printf("error: cannot get user cookie: %s\n", err)
		return
	}

	uid, err := users.GetUserID(cookie)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "delete.html", p)
		log.Printf("error: cannot get user id: %s\n", err)
		return
	}

	// get the list of events created by this user
	el, err := events.GetEventsByUserID(uid)
	if err != nil {
		c.HTML(http.StatusInternalServerError, "delete.html", p)
		log.Printf("error: cannot get user events: %s\n", err)
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
		log.Println("error: user trying to delete event created by another one")
		return
	}

	// delete event by event ID
	if err := events.Delete(eventID); err != nil {
		log.Printf("error: cannot delete event '%s': %s\n", eventID, err)
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
		log.Printf("error: admin: cannot get tot num of events: %s\n", err)
		return
	}

	p.NumOfUsers, err = users.GetNumOfUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Printf("error: admin: cannot get tot num of users: %s\n", err)
		return
	}

	p.NumOfBannedUsers, err = users.GetNumOfBannedUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Printf("error: admin: cannot get tot num of banned users: %s\n", err)
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

	log.Printf("admin: action: %s, event ID: %s\n", action, eventID)

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
		log.Printf("error: admin: cannot get tot num of events: %s\n", err)
		return
	}

	p.NumOfUsers, err = users.GetNumOfUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Printf("error: admin: cannot get tot num of users: %s\n", err)
		return
	}

	p.NumOfBannedUsers, err = users.GetNumOfBannedUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Printf("error: admin: cannot get tot num of banned users: %s\n", err)
		return
	}

	if eventID == "" {
		p.Error = true
		p.ErrMsg = "L'event ID est vide."
		c.HTML(http.StatusBadRequest, "admin.html", p)
		return
	}

	switch action {
	case "supprimer":
		if err = events.Delete(eventID); err != nil {
			p.Error = true
			p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
			c.HTML(http.StatusInternalServerError, "admin.html", p)
			log.Printf("error: admin: cannot delete event '%s': %s\n", eventID, err)
			return
		}

		p.Success = true
		p.SuccessMsg = "L'évènement a été supprimé avec succès."
		log.Printf("admin: deleted eventID '%s'\n", eventID)
		c.HTML(http.StatusOK, "admin.html", p)
	case "modifier":
		p.Event, err = events.GetEventByID(eventID, false)
		if err != nil {
			p.Error = true
			p.ErrMsg = fmt.Sprintf("Une erreur est survenue lors de la récupération de l'évènement: %s", err)
			c.HTML(http.StatusInternalServerError, "admin.html", p)
			log.Printf("error: admin: cannot get event with id '%s': %s\n", eventID, err)
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

		log.Printf("admin: updating eventID '%s'\n", eventID)
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
	log.Printf("admin: banning userID: %s\n", userID)

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
		log.Printf("error: admin: cannot get tot num of events: %s\n", err)
		return
	}

	p.NumOfUsers, err = users.GetNumOfUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Printf("error: admin: cannot get tot num of users: %s\n", err)
		return
	}

	p.NumOfBannedUsers, err = users.GetNumOfBannedUsers()
	if err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Printf("error: admin: cannot get tot num of banned users: %s\n", err)
		return
	}

	if userID == "" {
		p.Error = true
		p.ErrMsg = "L'user ID est vide."
		c.HTML(http.StatusBadRequest, "admin.html", p)
		return
	}

	if err := users.Ban(userID); err != nil {
		p.Error = true
		p.ErrMsg = fmt.Sprintf("Une erreur est survenue: %s", err)
		c.HTML(http.StatusInternalServerError, "admin.html", p)
		log.Printf("error: admin: cannot ban userID '%s': %s\n", userID, err)
		return
	}

	p.Success = true
	p.SuccessMsg = "L'utilisateur·rice a été banni."
	log.Printf("admin: banned userID '%s'\n", userID)
	c.HTML(http.StatusOK, "admin.html", p)
}

/*
	Confirmation process handler

	This handler checks if a confirmation token received by email is valid or not
*/
func confirmationProcess(c *gin.Context) {
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

	token := c.Param("token")
	if !mail.ValidateConfirmationToken(token) {
		p.Error = true
		p.ErrMsg = "Le token est invalide."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		return
	}

	sessionToken, err := c.Cookie(config.SessionCookieName)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Il semblerait que tu aies été déconnecté·e."
		c.HTML(http.StatusUnauthorized, "account.html", p)
		return
	}

	uid, err := users.GetUserID(sessionToken)
	if err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "account.html", p)
		log.Printf("error: cannot retrieve user ID: %s\n", err)
		return
	}

	if err := users.ValidateAccount(uid); err != nil {
		p.Error = true
		p.ErrMsg = "Une erreur est survenue."
		c.HTML(http.StatusInternalServerError, "account.html", p)
		log.Printf("error: cannot validate user account with ID '%s': %s\n", uid, err)
		return
	}

	p.HasConfirmedAccount = true
	p.HasMsg = true
	p.Msg = "Ton compte a été validé ! Tu peux dorénavant publier des évènements."
	c.HTML(http.StatusOK, "account.html", p)
}
