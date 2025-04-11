package handlers

import (
	"SmartStudyBot/db"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
)

// Global variables for JWT and session store.
var jwtKey []byte
var store *sessions.CookieStore

// init loads environment variables and sets up global keys.
func init() {
	// Load environment variables from .env file.
	if err := godotenv.Load(); err != nil {
		fmt.Println("Warning: .env file not found; using system environment variables")
	}
	jwtKey = []byte(os.Getenv("JWT_SECRET"))
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   72 * 3600, // 72 hours
		HttpOnly: true,
	}
	fmt.Println("handlers init: JWT_SECRET =", string(jwtKey))
	fmt.Println("handlers init: SESSION_SECRET =", os.Getenv("SESSION_SECRET"))
}

// WebPageData holds common template data.
type WebPageData struct {
	WebsiteTitle                 string
	H1Heading                    string
	BodyParagraphText            string
	PostResponseMessage          string
	PosrResponseHTTPResponseCode string
}

// renderTemplate loads a template file from the "templates" folder and executes it.
func renderTemplate(w http.ResponseWriter, tmpl string, data any) {
	tmplPath := filepath.Join("templates", tmpl+".html")
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}

// generateRandomString returns a random hexadecimal string.
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "randomerror123"
	}
	return hex.EncodeToString(bytes)
}

// GenerateJWT creates a JWT token for the provided username.
func GenerateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(), // Token valid for 1 hour
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// ----------------------- Basic Handlers ------------------------

// HomeHandler renders the home page.
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "home", nil)
}

// LoginHandler renders the login page.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	data := WebPageData{
		WebsiteTitle:      "Smart Study Bot - Login",
		H1Heading:         "Login to Smart Study Bot",
		BodyParagraphText: "Please enter your login credentials",
	}
	renderTemplate(w, "login", data)
}

// LoginCheckHandler processes login submission using bcrypt for password validation.
func LoginCheckHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	fmt.Printf("Login attempt: username=[%s]\n", username)

	valid, err := db.ValidateUser(username, password)
	if err != nil {
		fmt.Println("DB error:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	if !valid {
		fmt.Printf("Invalid username/password for: %s\n", username)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var role string
	err = db.DB.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&role)
	if err != nil {
		fmt.Println("Error retrieving role:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(72 * time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		fmt.Println("Token generation error:", err)
		http.Error(w, "Could not login", http.StatusInternalServerError)
		return
	}

	session, _ := store.Get(r, "smartstudy-session")
	session.Values["username"] = username
	session.Values["authenticatedUser"] = true
	err = session.Save(r, w)
	if err != nil {
		fmt.Println("Session save error:", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	fmt.Println("Session saved for:", username)

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(72 * time.Hour),
	})
	fmt.Println("JWT token set for:", username)

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// RegisterHandler processes user registration.
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	data := WebPageData{
		WebsiteTitle:      "Smart Study Bot - Register",
		H1Heading:         "Register",
		BodyParagraphText: "Enter your registration details.",
	}

	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		email := strings.TrimSpace(r.FormValue("email"))
		password := strings.TrimSpace(r.FormValue("password"))
		// CreateUser now handles bcrypt in the db package.
		id, err := db.CreateUser(username, email, password, "student")
		if err != nil {
			data.PostResponseMessage = "Registration failed, please contact administrator."
		} else {
			data.PostResponseMessage = "Registration successful for " + username + " (User ID: " + strconv.Itoa(int(id)) + ")"
		}
	}

	renderTemplate(w, "register", data)
}

// DashboardHandler renders either the tutor or student dashboard based on session.
// For students, it fetches assignments and quizzes.
func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DashboardHandler: reached")
	session, _ := store.Get(r, "smartstudy-session")
	user, ok := session.Values["username"].(string)
	if !ok || user == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var role string
	err := db.DB.QueryRow("SELECT role FROM users WHERE username = ?", user).Scan(&role)
	if err != nil {
		http.Error(w, "Error retrieving user role", http.StatusInternalServerError)
		return
	}
	role = strings.ToLower(role)

	if role == "tutor" {
		renderTemplate(w, "tutor_dashboard", map[string]string{
			"Username": user,
			"Role":     "Tutor",
		})
		return
	}

	// For students, fetch assignments and quizzes.
	type Assignment struct {
		Title       string
		Description string
		FilePath    string
		CreatedAt   string
	}
	type Quiz struct {
		ID        int
		Title     string
		CreatedAt string
	}

	assignments := []Assignment{}
	rows, err := db.DB.Query(`SELECT title, description, file_path, created_at FROM assignments ORDER BY created_at DESC LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a Assignment
			rows.Scan(&a.Title, &a.Description, &a.FilePath, &a.CreatedAt)
			assignments = append(assignments, a)
		}
	}

	quizzes := []Quiz{}
	rows2, err := db.DB.Query(`SELECT id, title, created_at FROM quizzes ORDER BY created_at DESC LIMIT 5`)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var q Quiz
			rows2.Scan(&q.ID, &q.Title, &q.CreatedAt)
			quizzes = append(quizzes, q)
		}
	}

	data := struct {
		Username    string
		Assignments []Assignment
		Quizzes     []Quiz
	}{
		Username:    user,
		Assignments: assignments,
		Quizzes:     quizzes,
	}

	renderTemplate(w, "student_dashboard", data)
}

// LogoutHandler clears the session and JWT cookie.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "smartstudy-session")
	delete(session.Values, "username")
	delete(session.Values, "authenticatedUser")
	session.Save(r, w)

	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// AuthMiddleware verifies the JWT token stored in the cookie.
func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("token")
		if err != nil {
			http.Error(w, "Unauthorized - No token", http.StatusUnauthorized)
			return
		}
		tokenStr := cookie.Value

		claims := &jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized - Invalid token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// ------------------ Tutor-specific Handlers ------------------

// CreateQuizHandler allows a tutor to create a quiz.
func CreateQuizHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "smartstudy-session")
	username, ok := session.Values["username"].(string)
	if !ok || strings.ToLower(username) != "tutor1" {
		http.Error(w, "Unauthorized - Only tutors can create quizzes", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	title := r.FormValue("title")
	question := r.FormValue("question")
	optionA := r.FormValue("optionA")
	optionB := r.FormValue("optionB")
	optionC := r.FormValue("optionC")
	optionD := r.FormValue("optionD")
	correctOption := r.FormValue("correctOption")
	explanation := r.FormValue("explanation")
	options := []string{optionA, optionB, optionC, optionD}
	quizID, err := db.CreateQuiz(title, question, options, correctOption, explanation)
	if err != nil {
		http.Error(w, "Error creating quiz", http.StatusInternalServerError)
		fmt.Println("DB error in CreateQuiz:", err)
		return
	}
	fmt.Fprintf(w, "Quiz created successfully with ID: %d", quizID)
}

// UploadAssignmentHandler allows a tutor to upload an assignment file.
func UploadAssignmentHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "smartstudy-session")
	username, ok := session.Values["username"].(string)
	if !ok || strings.ToLower(username) != "tutor1" {
		http.Error(w, "Unauthorized - Only tutors can upload assignments", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Error processing form", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("assignmentFile")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	title := r.FormValue("title")
	description := r.FormValue("description")
	uploadDir := filepath.Join("uploads", "assignments")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "Unable to create upload directory", http.StatusInternalServerError)
		return
	}
	filePath := filepath.Join(uploadDir, header.Filename)
	out, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Unable to create file on server", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	_, err = io.Copy(out, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	var tutorID int
	err = db.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&tutorID)
	if err != nil {
		http.Error(w, "Error retrieving tutor ID", http.StatusInternalServerError)
		return
	}
	assignmentID, err := db.CreateAssignment(tutorID, title, filePath, description)
	if err != nil {
		http.Error(w, "Error saving assignment details", http.StatusInternalServerError)
		fmt.Println("DB error in CreateAssignment:", err)
		return
	}
	fmt.Fprintf(w, "Assignment uploaded successfully with ID: %d", assignmentID)
}

// UploadMaterialHandler allows a tutor to upload study material.
func UploadMaterialHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "smartstudy-session")
	username, ok := session.Values["username"].(string)
	if !ok || strings.ToLower(username) != "tutor1" {
		http.Error(w, "Unauthorized - Only tutors can upload materials", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, "Error processing form", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("materialFile")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	title := r.FormValue("title")
	description := r.FormValue("description")
	content := r.FormValue("content")
	uploadDir := filepath.Join("uploads", "materials")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "Unable to create upload directory", http.StatusInternalServerError)
		return
	}
	filePath := filepath.Join(uploadDir, header.Filename)
	out, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Unable to create file on server", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	_, err = io.Copy(out, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	var tutorID int
	err = db.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&tutorID)
	if err != nil {
		http.Error(w, "Error retrieving tutor ID", http.StatusInternalServerError)
		return
	}
	materialID, err := db.CreateMaterial(tutorID, title, filePath, description, content)
	if err != nil {
		http.Error(w, "Error saving material details", http.StatusInternalServerError)
		fmt.Println("DB error in CreateMaterial:", err)
		return
	}
	fmt.Fprintf(w, "Material uploaded successfully with ID: %d", materialID)
}

// ------------------ Student Quiz Handlers ------------------

// AttemptQuizHandler fetches a quiz by ID from the URL, loads its questions, and renders a template.
func AttemptQuizHandler(w http.ResponseWriter, r *http.Request) {
	// Expect URL in format: /quiz/{id}
	quizIDStr := strings.TrimPrefix(r.URL.Path, "/quiz/")
	quizID, err := strconv.Atoi(quizIDStr)
	if err != nil {
		http.Error(w, "Invalid quiz ID", http.StatusBadRequest)
		return
	}

	type Question struct {
		ID       int
		Question string
		Options  []string
	}

	questions := []Question{}
	rows, err := db.DB.Query("SELECT id, question, options FROM quiz_questions WHERE quiz_id = ?", quizID)
	if err != nil {
		http.Error(w, "Error fetching quiz", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var q Question
		var optionsJSON string
		if err := rows.Scan(&q.ID, &q.Question, &optionsJSON); err != nil {
			http.Error(w, "Error scanning quiz questions", http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal([]byte(optionsJSON), &q.Options); err != nil {
			q.Options = []string{} // Fallback if parse fails
		}
		questions = append(questions, q)
	}

	data := struct {
		QuizID    int
		Questions []Question
	}{
		QuizID:    quizID,
		Questions: questions,
	}
	renderTemplate(w, "attempt_quiz", data)
}

// SubmitQuizHandler processes the student's quiz attempt.
func SubmitQuizHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	quizIDStr := r.FormValue("quiz_id")
	quizID, err := strconv.Atoi(quizIDStr)
	if err != nil {
		http.Error(w, "Invalid quiz ID", http.StatusBadRequest)
		return
	}

	session, _ := store.Get(r, "smartstudy-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var studentID int
	err = db.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&studentID)
	if err != nil {
		http.Error(w, "Error retrieving student ID", http.StatusInternalServerError)
		return
	}

	type Answer struct {
		QuestionID    int
		CorrectAnswer string
	}
	correctAnswers := make(map[int]string)
	rows, err := db.DB.Query("SELECT id, correct_option FROM quiz_questions WHERE quiz_id = ?", quizID)
	if err != nil {
		http.Error(w, "Error fetching quiz answers", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	totalQuestions := 0
	for rows.Next() {
		var ans Answer
		if err := rows.Scan(&ans.QuestionID, &ans.CorrectAnswer); err != nil {
			http.Error(w, "Error scanning quiz answers", http.StatusInternalServerError)
			return
		}
		correctAnswers[ans.QuestionID] = ans.CorrectAnswer
		totalQuestions++
	}

	correctCount := 0
	for qid, correctOpt := range correctAnswers {
		formField := fmt.Sprintf("answer_%d", qid)
		studentAnswer := strings.TrimSpace(r.FormValue(formField))
		if studentAnswer == correctOpt {
			correctCount++
		}
	}

	score := 0.0
	if totalQuestions > 0 {
		score = (float64(correctCount) / float64(totalQuestions)) * 100
	}

	// Record the quiz attempt into student_quiz_attempts table.
	err = db.RecordStudentQuiz(studentID, score, totalQuestions, correctCount)
	if err != nil {
		http.Error(w, "Error recording quiz attempt", http.StatusInternalServerError)
		return
	}

	data := struct {
		Score          float64
		TotalQuestions int
		CorrectAnswers int
	}{
		Score:          score,
		TotalQuestions: totalQuestions,
		CorrectAnswers: correctCount,
	}
	renderTemplate(w, "quiz_submitted", data)
}

// TutorProgressHandler allows a tutor to view student quiz attempts.
func TutorProgressHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "smartstudy-session")
	username, ok := session.Values["username"].(string)
	if !ok || strings.ToLower(username) != "tutor1" {
		http.Error(w, "Unauthorized - Only tutors can view progress", http.StatusUnauthorized)
		return
	}

	type QuizAttempt struct {
		StudentUsername string
		QuizTitle       string
		Score           float64
		TotalQuestions  int
		CorrectAnswers  int
		SubmittedAt     string
	}
	attempts := []QuizAttempt{}
	query := `
		SELECT u.username, q.title, a.score, a.total_questions, a.correct_answers, a.submitted_at
		FROM student_quiz_attempts a
		JOIN users u ON a.student_id = u.id
		JOIN quizzes q ON a.quiz_id = q.id
		ORDER BY a.submitted_at DESC`
	rows2, err := db.DB.Query(query)
	if err != nil {
		http.Error(w, "Error retrieving progress data", http.StatusInternalServerError)
		return
	}
	defer rows2.Close()
	for rows2.Next() {
		var attempt QuizAttempt
		if err := rows2.Scan(&attempt.StudentUsername, &attempt.QuizTitle, &attempt.Score, &attempt.TotalQuestions, &attempt.CorrectAnswers, &attempt.SubmittedAt); err != nil {
			http.Error(w, "Error scanning progress data", http.StatusInternalServerError)
			return
		}
		attempts = append(attempts, attempt)
	}
	data := struct {
		Attempts []QuizAttempt
	}{
		Attempts: attempts,
	}
	renderTemplate(w, "tutor_progress", data)
}
