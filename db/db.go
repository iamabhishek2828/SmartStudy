package db

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

// InitDB establishes a connection to the MySQL database.
func InitDB() {
	// DSN: username:password@tcp(host:port)/dbname?parseTime=true
	// Note: "abhi@28" is URL-encoded as "abhi%4028"
	dsn := "abhishek:abhi@28@tcp(127.0.0.1:3306)/smartstudy?parseTime=true"
	var err error
	DB, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("Error opening DB:", err)
	}
	if err = DB.Ping(); err != nil {
		log.Fatal("Error pinging DB:", err)
	}
	fmt.Println("Connected to MySQL database!")
}

// CreateUser inserts a new user into the users table after hashing the password.
// In production, use bcrypt for security.
func CreateUser(username, email, password, role string) (int64, error) {
	// Hash the password with bcrypt.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, fmt.Errorf("error hashing password: %v", err)
	}

	query := `
        INSERT INTO users (username, email, password_hash, role, created_at, updated_at)
        VALUES (?, ?, ?, ?, NOW(), NOW())
        ON DUPLICATE KEY UPDATE role=VALUES(role), updated_at=NOW()`
	res, err := DB.Exec(query, username, email, string(hashedPassword), role)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ValidateUser checks whether the provided password matches the hashed password stored in the database.
func ValidateUser(username, password string) (bool, error) {
	var hashedPassword string
	err := DB.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&hashedPassword)
	if err != nil {
		return false, err
	}
	// Compare the hashed password with the input password using bcrypt.
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, nil
	}
	return true, nil
}

// CreateQuiz creates a new quiz with a title and returns the quiz ID.
func CreateQuiz(title string) (int64, error) {
	query := "INSERT INTO quizzes (title, created_at) VALUES (?, NOW())"
	res, err := DB.Exec(query, title)
	if err != nil {
		return 0, fmt.Errorf("error creating quiz: %v", err)
	}
	return res.LastInsertId()
}

// AddQuestionToQuiz adds a new question to an existing quiz.
func AddQuestionToQuiz(quizID int64, question string, options []string, correctOption, explanation string) error {
	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return fmt.Errorf("error marshaling options: %v", err)
	}

	query := `
		INSERT INTO quiz_questions (quiz_id, question, options, correct_option, explanation, created_at)
		VALUES (?, ?, ?, ?, ?, NOW())`
	_, err = DB.Exec(query, quizID, question, string(optionsJSON), correctOption, explanation)
	return err
}

// CreateAssignment inserts a new assignment record into the assignments table.
// It accepts tutorID, title, filePath, and description.
func CreateAssignment(tutorID int, title, filePath, description string) (int64, error) {
	query := "INSERT INTO assignments (tutor_id, title, file_path, description, created_at) VALUES (?, ?, ?, ?, NOW())"
	res, err := DB.Exec(query, tutorID, title, filePath, description)
	if err != nil {
		return 0, fmt.Errorf("error creating assignment: %v", err)
	}
	return res.LastInsertId()
}

// CreateMaterial inserts a new study material record into the materials table.
// It accepts tutorID, title, filePath, description, and content.
func CreateMaterial(tutorID int, title, filePath, description, content string) (int64, error) {
	query := "INSERT INTO materials (tutor_id, title, file_path, description, content, created_at) VALUES (?, ?, ?, ?, ?, NOW())"
	res, err := DB.Exec(query, tutorID, title, filePath, description, content)
	if err != nil {
		return 0, fmt.Errorf("error creating study material: %v", err)
	}
	return res.LastInsertId()
}

// RecordStudentQuiz stores a student's quiz attempt in the quizzes table.
func RecordStudentQuiz(studentID int, score float64, totalQ, correctAns int) error {
	query := `
		INSERT INTO quizzes (student_id, score, total_question, correct_answers)
		VALUES (?, ?, ?, ?)`
	_, err := DB.Exec(query, studentID, score, totalQ, correctAns)
	if err != nil {
		return fmt.Errorf("error recording student quiz: %v", err)
	}
	return nil
}

// RecordStudentQuizAttempt records a student's quiz attempt into the student_quiz_attempts table.
func RecordStudentQuizAttempt(studentID, quizID int, score float64, totalQ, correctAns int) error {
	query := `
      INSERT INTO student_quiz_attempts (student_id, quiz_id, score, total_questions, correct_answers)
      VALUES (?, ?, ?, ?, ?)`
	_, err := DB.Exec(query, studentID, quizID, score, totalQ, correctAns)
	return err
}
