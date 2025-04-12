# CasaConnect

## 🏡 About CasaConnect

CasaConnect is an MVC web application built with .NET C# to assist people in finding their ideal home. The platform allows users to search for properties, view listings, and connect with real estate agents or property owners.

## 🚀 Features

- User authentication (Login/Register)
- Property listing with images and details
- Search and filter functionality
- Contact property owners directly
- Favorites and saved listings
- Admin dashboard for managing listings

## 🛠️ Technologies Used

- **Frontend:** Razor Views, Bootstrap, JavaScript
- **Backend:** .NET Core MVC, C#
- **Database:** SQL Server, Entity Framework Core
- **Authentication:** Identity Framework
- **Version Control:** Git & GitHub

## 🛆 Installation & Setup

### Prerequisites

Ensure you have the following installed:

- .NET SDK
- SQL Server
- Visual Studio or VS Code

### Steps

1. Clone the repository:
   ```sh
   git clone https://github.com/Levi-LMN/Casa-Connect.git
   cd Casa-Connect
   ```
2. Restore dependencies:
   ```sh
   dotnet restore
   ```
3. Create and apply database migrations:
   ```sh
   dotnet ef migrations add InitialCreate
   dotnet ef database update
   ```
4. Run the application:
   ```sh
   dotnet run
   ```
5. Open your browser and go to `http://localhost:5000`

## 🤝 Contributing

Contributions are welcome! Follow these steps:

1. Fork the repository.
2. Create a new branch: `git checkout -b feature-branch`
3. Commit your changes: `git commit -m "Added a new feature"`
4. Push to your branch: `git push origin feature-branch`
5. Create a pull request.

## 📝 License

This project is licensed under the MIT License.

---

🌟 *Happy Coding!*

Project collaborators : Eve and Lewis
