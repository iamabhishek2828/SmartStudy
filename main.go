package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/iamabhishek2828/SmartStudy/db"
	"github.com/iamabhishek2828/SmartStudy/handlers"
	"github.com/joho/godotenv"
)

func init() {
	if os.Getenv("RENDER") == "" {
		_ = godotenv.Load()
	}
	{
		fmt.Println("Loaded .env file successfully.")
	}
}
func main() {
	db.InitDB()
	defer db.DB.Close()

	mux := http.NewServeMux()

	// static assets
	fs := http.FileServer(http.Dir("resource"))
	mux.Handle("/resource/", http.StripPrefix("/resource/", fs))
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	// public routes
	mux.HandleFunc("/", handlers.HomeHandler)
	mux.HandleFunc("/register", handlers.RegisterHandler)
	mux.HandleFunc("/login", handlers.LoginHandler)
	mux.HandleFunc("/login_check", handlers.LoginCheckHandler)

	// authenticated routes
	mux.HandleFunc("/dashboard", handlers.AuthMiddleware(handlers.DashboardHandler))
	mux.HandleFunc("/logout", handlers.LogoutHandler)

	// student quiz routes
	mux.HandleFunc("/quiz/", handlers.AuthMiddleware(handlers.AttemptQuizHandler))
	mux.HandleFunc("/submit_quiz", handlers.AuthMiddleware(handlers.SubmitQuizHandler))

	// tutor progress
	mux.HandleFunc("/tutor_progress", handlers.AuthMiddleware(handlers.TutorProgressHandler))

	// tutor-only routes
	mux.HandleFunc("/create_quiz_form", handlers.AuthMiddleware(handlers.ShowCreateQuizForm))
	mux.HandleFunc("/create_quiz", handlers.AuthMiddleware(handlers.CreateQuizHandler))
	mux.HandleFunc("/upload_assignment", handlers.AuthMiddleware(handlers.UploadAssignmentHandler))
	mux.HandleFunc("/upload_material", handlers.AuthMiddleware(handlers.UploadMaterialHandler))
	mux.HandleFunc("/add_question", handlers.AuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			handlers.HandleAddQuestion(w, r)
		} else {
			handlers.ShowAddQuestionForm(w, r)
		}
	}))
	mux.HandleFunc("/submit_assignment", handlers.AuthMiddleware(handlers.SubmitAssignmentHandler))
	mux.HandleFunc("/view_submissions", handlers.AuthMiddleware(handlers.ViewSubmissionsHandler))
	mux.HandleFunc("/evaluate_submission", handlers.AuthMiddleware(handlers.EvaluateSubmissionHandler))
	mux.HandleFunc("/post_study_plan", handlers.AuthMiddleware(handlers.PostStudyPlanHandler))

	fmt.Println("✅ Server running at http://localhost:8000/")
	log.Fatal(http.ListenAndServe(":8000", mux))
}
