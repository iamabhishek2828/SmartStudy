package handlers

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/iamabhishek2828/SmartStudy/db"

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

type Submission struct {
	CreatedAt time.Time
	Grade     string
	Feedback  string
}

type Assignment struct {
	ID          int
	Title       string
	Description string
	FilePath    string
	CreatedAt   string
	DueDate     time.Time
	Submission  *Submission
}

type StudyPlan struct {
	PlanDetails string
	ExamDate    time.Time
}

func renderTemplate(w http.ResponseWriter, tmpl string, data any) {
	funcMap := template.FuncMap{
		"now": time.Now,
		"lt":  func(a, b time.Time) bool { return a.Before(b) },
	}
	tmplPath := filepath.Join("templates", tmpl+".html")
	t, err := template.New(filepath.Base(tmplPath)).Funcs(funcMap).ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, "Error loading template", http.StatusInternalServerError)
		fmt.Println("TEMPLATE ERROR:", err)
		return
	}
	if err := t.Execute(w, data); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		fmt.Println("TEMPLATE EXEC ERROR:", err)
	}
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

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	data := WebPageData{
		WebsiteTitle:      "Smart Study Bot – Register",
		H1Heading:         "Register",
		BodyParagraphText: "Enter your registration details.",
	}

	if r.Method == http.MethodPost {
		username := strings.TrimSpace(r.FormValue("username"))
		email := strings.TrimSpace(r.FormValue("email"))
		password := strings.TrimSpace(r.FormValue("password"))
		role := strings.ToLower(r.FormValue("role"))
		if role != "tutor" && role != "student" {
			role = "student"
		}

		id, err := db.CreateUser(username, email, password, role)
		if err != nil {
			if me, ok := err.(*mysql.MySQLError); ok && me.Number == 1062 {
				data.PostResponseMessage = "❌ That username is already taken. Please choose another."
			} else {
				data.PostResponseMessage = "Registration failed, please contact administrator."
				fmt.Println("CreateUser error:", err)
			}
		} else {
			data.PostResponseMessage = fmt.Sprintf(
				"✅ Registration successful for %s (%s) with ID: %d",
				username, role, id,
			)
		}
	}

	renderTemplate(w, "register", data)
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

	valid, err := db.ValidateUser(username, password)
	if err != nil {
		log.Printf("DB error during login: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	if !valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var role string
	if err := db.DB.QueryRow(
		"SELECT role FROM users WHERE username = ?",
		username,
	).Scan(&role); err != nil {
		log.Printf("error retrieving role for %s: %v", username, err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(72 * time.Hour).Unix(),
	}).SignedString(jwtKey)
	if err != nil {
		log.Printf("JWT error: %v", err)
		http.Error(w, "Could not login", http.StatusInternalServerError)
		return
	}
	sess, _ := store.Get(r, "smartstudy-session")
	sess.Values["username"] = username
	sess.Values["role"] = role
	if err := sess.Save(r, w); err != nil {
		log.Printf("session save error: %v", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(72 * time.Hour),
	})

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func DashboardHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, "smartstudy-session")
	user, userOK := sess.Values["username"].(string)
	role, roleOK := sess.Values["role"].(string)
	if !userOK || !roleOK || user == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if strings.ToLower(role) == "tutor" {
		assignments := []Assignment{}
		rows, err := db.DB.Query(`SELECT id, title, description FROM assignments WHERE tutor_id = (SELECT id FROM users WHERE username = ?)`, user)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var a Assignment
				rows.Scan(&a.ID, &a.Title, &a.Description)
				assignments = append(assignments, a)
			}
		}
		type RecentSubmission struct {
			AssignmentID    int
			AssignmentTitle string
			Student         string
			FilePath        string
		}
		recentSubmissions := []RecentSubmission{}
		rows2, err := db.DB.Query(`
			SELECT s.assignment_id, a.title, u.username, s.file_path
			FROM submissions s
			JOIN assignments a ON s.assignment_id = a.id
			JOIN users u ON s.student_id = u.id
			WHERE a.tutor_id = (SELECT id FROM users WHERE username = ?)
			ORDER BY s.submitted_at DESC LIMIT 5
		`, user)
		if err == nil {
			defer rows2.Close()
			for rows2.Next() {
				var rs RecentSubmission
				rows2.Scan(&rs.AssignmentID, &rs.AssignmentTitle, &rs.Student, &rs.FilePath)
				recentSubmissions = append(recentSubmissions, rs)
			}
		}

		renderTemplate(w, "tutor_dashboard", struct {
			Username          string
			Assignments       []Assignment
			RecentSubmissions []RecentSubmission
		}{
			Username:          user,
			Assignments:       assignments,
			RecentSubmissions: recentSubmissions,
		})
		return
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
	rows, err := db.DB.Query(`SELECT id, title, description, file_path, created_at, due_date FROM assignments ORDER BY created_at DESC LIMIT 5`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var a Assignment
			rows.Scan(&a.ID, &a.Title, &a.Description, &a.FilePath, &a.CreatedAt, &a.DueDate)
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
	var studentID int
	err = db.DB.QueryRow("SELECT id FROM users WHERE username = ?", user).Scan(&studentID)
	if err != nil {
		studentID = 0
	}

	plans := []StudyPlan{}
	rows4, err := db.DB.Query(`
		SELECT plan_details, exam_date 
		FROM study_plans 
		WHERE student_id = ? AND exam_date = CURDATE()
	`, studentID)
	if err == nil {
		defer rows4.Close()
		for rows4.Next() {
			var sp StudyPlan
			rows4.Scan(&sp.PlanDetails, &sp.ExamDate)
			plans = append(plans, sp)
		}
	}

	data := struct {
		Username    string
		Assignments []Assignment
		Quizzes     []Quiz
		Materials   []Material
		StudyPlans  []StudyPlan
	}{
		Username:    user,
		Assignments: assignments,
		Quizzes:     quizzes,
		Materials:   materials,
		StudyPlans:  plans,
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
	_, ok := session.Values["username"].(string)
	role, roleOk := session.Values["role"].(string)

	if !ok || !roleOk || strings.ToLower(role) != "tutor" {
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
	sess, _ := store.Get(r, "smartstudy-session")
	role, ok := sess.Values["role"].(string)
	if !ok || strings.ToLower(role) != "tutor" {
		http.Error(w, "Unauthorized – Only tutors can upload assignments", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
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
	dueDateStr := r.FormValue("due_date")
	dueDate, err := time.Parse("2006-01-02", dueDateStr)
	if err != nil {
		http.Error(w, "Invalid due date", http.StatusBadRequest)
		return
	}
	uploadDir := filepath.Join("uploads", "assignments")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "Unable to create upload directory", http.StatusInternalServerError)
		return
	}

	dst := filepath.Join(uploadDir, header.Filename)
	out, err := os.Create(dst)
	if err != nil {
		http.Error(w, "Unable to create file on server", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	username, _ := sess.Values["username"].(string)
	var tutorID int
	if err := db.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&tutorID); err != nil {
		http.Error(w, "Error retrieving tutor ID", http.StatusInternalServerError)
		return
	}

	assignmentID, err := db.CreateAssignment(tutorID, title, dst, description, dueDate)
	if err != nil {
		http.Error(w, "Error saving assignment details", http.StatusInternalServerError)
		fmt.Println("DB error in CreateAssignment:", err)
		return
	}

	fmt.Fprintf(w, "Assignment uploaded successfully with ID: %d", assignmentID)
}

func UploadMaterialHandler(w http.ResponseWriter, r *http.Request) {
	sess, _ := store.Get(r, "smartstudy-session")
	role, ok := sess.Values["role"].(string)
	if !ok || strings.ToLower(role) != "tutor" {
		http.Error(w, "Unauthorized – Only tutors can upload materials", http.StatusUnauthorized)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
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

	dst := filepath.Join(uploadDir, header.Filename)
	out, err := os.Create(dst)
	if err != nil {
		http.Error(w, "Unable to create file on server", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	username, _ := sess.Values["username"].(string)
	var tutorID int
	if err := db.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&tutorID); err != nil {
		http.Error(w, "Error retrieving tutor ID", http.StatusInternalServerError)
		return
	}

	materialID, err := db.CreateMaterial(tutorID, title, dst, description, content)
	if err != nil {
		http.Error(w, "Error saving material details", http.StatusInternalServerError)
		fmt.Println("DB error in CreateMaterial:", err)
		return
	}

	fmt.Fprintf(w, "Material uploaded successfully with ID: %d", materialID)
}

func SubmitAssignmentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := store.Get(r, "smartstudy-session")
	username, ok := session.Values["username"].(string)
	if !ok || username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var studentID int
	if err := db.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&studentID); err != nil {
		http.Error(w, "Error retrieving student ID", http.StatusInternalServerError)
		return
	}
	assignmentID, err := strconv.Atoi(r.FormValue("assignment_id"))
	if err != nil {
		http.Error(w, "Invalid assignment ID", http.StatusBadRequest)
		return
	}
	fmt.Println("DEBUG: Submitting assignment", assignmentID, "for student", studentID)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Error processing form", http.StatusBadRequest)
		return
	}
	file, header, err := r.FormFile("submissionFile")
	if err != nil {
		http.Error(w, "Error retrieving the file", http.StatusBadRequest)
		return
	}
	defer file.Close()
	uploadDir := filepath.Join("uploads", "submissions")
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		http.Error(w, "Unable to create upload directory", http.StatusInternalServerError)
		return
	}
	dst := filepath.Join(uploadDir, fmt.Sprintf("%d_%s", studentID, header.Filename))
	out, err := os.Create(dst)
	if err != nil {
		http.Error(w, "Unable to create file on server", http.StatusInternalServerError)
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}
	res, err := db.DB.Exec(
		`INSERT INTO submissions (assignment_id, student_id, file_path, submitted_at) VALUES (?, ?, ?, NOW())`,
		assignmentID, studentID, dst,
	)
	if err != nil {
		fmt.Println("DEBUG: Error saving submission:", err)
		http.Error(w, "Error saving submission", http.StatusInternalServerError)
		return
	}
	id, _ := res.LastInsertId()
	fmt.Println("DEBUG: Submission saved with ID", id)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
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
	err = db.RecordStudentQuizAttempt(studentID, quizID, score, totalQuestions, correctCount)
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
	sess, _ := store.Get(r, "smartstudy-session")
	role, ok := sess.Values["role"].(string)
	if !ok || strings.ToLower(role) != "tutor" {
		http.Error(w, "Unauthorized – Only tutors can view progress", http.StatusUnauthorized)
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
	rows, err := db.DB.Query(query)
	if err != nil {
		http.Error(w, "Error retrieving progress data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var att QuizAttempt
		if err := rows.Scan(
			&att.StudentUsername,
			&att.QuizTitle,
			&att.Score,
			&att.TotalQuestions,
			&att.CorrectAnswers,
			&att.SubmittedAt,
		); err != nil {
			http.Error(w, "Error scanning progress data", http.StatusInternalServerError)
			return
		}
		attempts = append(attempts, att)
	}

	renderTemplate(w, "tutor_progress", struct{ Attempts []QuizAttempt }{attempts})
}

func ViewSubmissionsHandler(w http.ResponseWriter, r *http.Request) {
	assignmentIDStr := r.URL.Query().Get("assignment_id")
	assignmentID, err := strconv.Atoi(assignmentIDStr)
	if err != nil {
		http.Error(w, "Invalid assignment ID", http.StatusBadRequest)
		return
	}

	type SubmissionRow struct {
		ID          int
		Student     string
		FilePath    string
		SubmittedAt string
		Evaluated   bool
		Marks       sql.NullInt64
		Feedback    sql.NullString
	}

	rows, err := db.DB.Query(`
        SELECT s.id, u.username, s.file_path, s.submitted_at, s.evaluated, s.marks, s.feedback
        FROM submissions s
        JOIN users u ON s.student_id = u.id
        WHERE s.assignment_id = ?
    `, assignmentID)
	if err != nil {
		http.Error(w, "Error fetching submissions", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var submissions []SubmissionRow
	for rows.Next() {
		var s SubmissionRow
		if err := rows.Scan(&s.ID, &s.Student, &s.FilePath, &s.SubmittedAt, &s.Evaluated, &s.Marks, &s.Feedback); err != nil {
			http.Error(w, "Error scanning submissions", http.StatusInternalServerError)
			return
		}
		submissions = append(submissions, s)
	}

	data := struct {
		AssignmentID int
		Submissions  []SubmissionRow
	}{
		AssignmentID: assignmentID,
		Submissions:  submissions,
	}

	renderTemplate(w, "view_submissions", data)
}

func EvaluateSubmissionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	submissionID, _ := strconv.Atoi(r.FormValue("submission_id"))
	marks, _ := strconv.Atoi(r.FormValue("marks"))
	feedback := r.FormValue("feedback")

	_, err := db.DB.Exec(`UPDATE submissions SET evaluated=1, marks=?, feedback=? WHERE id=?`, marks, feedback, submissionID)
	if err != nil {
		http.Error(w, "Failed to update submission", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusSeeOther)
}

func PostStudyPlanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sess, _ := store.Get(r, "smartstudy-session")
	role, ok := sess.Values["role"].(string)
	if !ok || strings.ToLower(role) != "tutor" {
		http.Error(w, "Unauthorized – Only tutors can post study plans", http.StatusUnauthorized)
		return
	}

	studentUsername := r.FormValue("student_username")
	planDetails := r.FormValue("plan_details")
	examDateStr := r.FormValue("exam_date")
	examDate, err := time.Parse("2006-01-02", examDateStr)
	if err != nil {
		http.Error(w, "Invalid exam date", http.StatusBadRequest)
		return
	}

	var studentID int
	err = db.DB.QueryRow("SELECT id FROM users WHERE username = ?", studentUsername).Scan(&studentID)
	if err != nil {
		http.Error(w, "Student not found", http.StatusBadRequest)
		return
	}

	_, err = db.DB.Exec(
		`INSERT INTO study_plans (student_id, plan_details, exam_date) VALUES (?, ?, ?)`,
		studentID, planDetails, examDate,
	)
	if err != nil {
		http.Error(w, "Failed to post study plan", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}
