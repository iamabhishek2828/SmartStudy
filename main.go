package main

import (
	"fmt"
	"log"
	"net/http"

	"SmartStudyBot/db"
	"SmartStudyBot/handlers"

	"github.com/joho/godotenv"
)

// init loads the environment variables.
func init() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Warning: No .env file found; using system environment variables")
	} else {
		fmt.Println("Loaded .env file successfully.")
	}
}

func main() {
	db.InitDB()
	defer db.DB.Close()

	mux := http.NewServeMux()

	// Serve static files from the resource folder.
	fs := http.FileServer(http.Dir("resource"))
	mux.Handle("/resource/", http.StripPrefix("/resource/", fs))
	mux.Handle("/uploads/", http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))
	// Route handlers.
	mux.HandleFunc("/", handlers.HomeHandler)
	mux.HandleFunc("/register", handlers.RegisterHandler)
	mux.HandleFunc("/login_check", handlers.LoginCheckHandler)
	mux.HandleFunc("/login", handlers.LoginHandler)
	mux.HandleFunc("/dashboard", handlers.AuthMiddleware(handlers.DashboardHandler))
	mux.HandleFunc("/logout", handlers.LogoutHandler)
	mux.HandleFunc("/quiz/", handlers.AuthMiddleware(handlers.AttemptQuizHandler))
	// e.g., /quiz/123
	mux.HandleFunc("/submit_quiz", handlers.AuthMiddleware(handlers.SubmitQuizHandler))
	mux.HandleFunc("/tutor_progress", handlers.AuthMiddleware(handlers.TutorProgressHandler))

	// Tutor-specific routes.
	mux.HandleFunc("/create_quiz", handlers.AuthMiddleware(handlers.CreateQuizHandler))
	mux.HandleFunc("/upload_assignment", handlers.AuthMiddleware(handlers.UploadAssignmentHandler))
	mux.HandleFunc("/upload_material", handlers.AuthMiddleware(handlers.UploadMaterialHandler))

	fmt.Println("✅ Server running at http://localhost:8000/")
	log.Fatal(http.ListenAndServe(":8000", mux))
}
