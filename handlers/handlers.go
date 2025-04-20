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

var jwtKey []byte
var store *sessions.CookieStore

func init() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Warning: .env file not found; using system environment variables")
	}
	jwtKey = []byte(os.Getenv("JWT_SECRET"))
	store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   72 * 3600,
		HttpOnly: true,
	}
	fmt.Println("handlers init: JWT_SECRET =", string(jwtKey))
	fmt.Println("handlers init: SESSION_SECRET =", os.Getenv("SESSION_SECRET"))
}

type WebPageData struct {
	WebsiteTitle                 string
	H1Heading                    string
	BodyParagraphText            string
	PostResponseMessage          string
	PosrResponseHTTPResponseCode string
}

func renderTemplate(w http.ResponseWriter, tmpl string, data any) {
	tmplPath := filepath.Join("templates", tmpl+".html")
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		return
	}
	t.Execute(w, data)
}
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "randomerror123"
	}
	return hex.EncodeToString(bytes)
}
func GenerateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "home", nil)
}
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	data := WebPageData{
		WebsiteTitle:      "Smart Study Bot - Login",
		H1Heading:         "Login to Smart Study Bot",
		BodyParagraphText: "Please enter your login credentials",
	}
	renderTemplate(w, "login", data)
}
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
	session.Values["role"] = role
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
		role := strings.ToLower(strings.TrimSpace(r.FormValue("role")))
		if role != "tutor" && role != "student" {
			role = "student"
		}

		id, err := db.CreateUser(username, email, password, role)
		if err != nil {
			data.PostResponseMessage = "Registration failed, please contact administrator."
		} else {
			data.PostResponseMessage = "Registration successful for " + username + " (" + role + ") with ID: " + strconv.FormatInt(id, 10)

		}
	}

	renderTemplate(w, "register", data)
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DashboardHandler: reached")
	session, _ := store.Get(r, "smartstudy-session")
	user, ok := session.Values["username"].(string)
	role, roleOK := session.Values["role"].(string)
	if !ok || user == "" || !roleOK || role == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
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
	type Material struct {
		Title       string
		Description string
		FilePath    string
		CreatedAt   string
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
	materials := []Material{}
	rows3, err := db.DB.Query(`SELECT title, description, file_path, created_at FROM materials ORDER BY created_at DESC LIMIT 5`)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var m Material
			rows3.Scan(&m.Title, &m.Description, &m.FilePath, &m.CreatedAt)
			materials = append(materials, m)
		}
	}

	data := struct {
		Username    string
		Assignments []Assignment
		Quizzes     []Quiz
		Materials   []Material
	}{
		Username:    user,
		Assignments: assignments,
		Quizzes:     quizzes,
		Materials:   materials,
	}

	renderTemplate(w, "student_dashboard", data)
}
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
func ShowCreateQuizForm(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "create_quiz", nil)
}
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
	quizID, err := db.CreateQuiz(title)
	if err != nil {
		http.Error(w, "Error creating quiz", http.StatusInternalServerError)
		fmt.Println("DB error in CreateQuiz:", err)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/add_question?quiz_id=%d", quizID), http.StatusSeeOther)
}
func ShowAddQuestionForm(w http.ResponseWriter, r *http.Request) {
	quizID := r.URL.Query().Get("quiz_id")
	qID, err := strconv.Atoi(quizID)
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
	rows, err := db.DB.Query("SELECT id, question, options FROM quiz_questions WHERE quiz_id = ?", qID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var q Question
			var optionsJSON string
			if err := rows.Scan(&q.ID, &q.Question, &optionsJSON); err != nil {
				http.Error(w, "Error scanning quiz questions", http.StatusInternalServerError)
				return
			}
			if err := json.Unmarshal([]byte(optionsJSON), &q.Options); err != nil {
				q.Options = []string{}
			}
			questions = append(questions, q)
		}
	} else {
		fmt.Println("Error fetching questions:", err)
	}
	data := struct {
		QuizID    string
		Questions []Question
	}{
		QuizID:    quizID,
		Questions: questions,
	}
	renderTemplate(w, "add_question", data)
}
func HandleAddQuestion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	quizIDStr := r.FormValue("quiz_id")
	quizID, err := strconv.ParseInt(quizIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid quiz ID", http.StatusBadRequest)
		return
	}

	question := r.FormValue("question")
	optionA := r.FormValue("optionA")
	optionB := r.FormValue("optionB")
	optionC := r.FormValue("optionC")
	optionD := r.FormValue("optionD")
	correctOption := r.FormValue("correctOption")
	explanation := r.FormValue("explanation")

	options := []string{optionA, optionB, optionC, optionD}

	err = db.AddQuestionToQuiz(quizID, question, options, correctOption, explanation)
	if err != nil {
		http.Error(w, "Failed to add question", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/add_question?quiz_id=%d", quizID), http.StatusSeeOther)
}
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
func AttemptQuizHandler(w http.ResponseWriter, r *http.Request) {
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
			q.Options = []string{}
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
