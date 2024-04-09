# TeamLinkHub

## Overview

TeamLinkHub is a cutting-edge communication platform inspired by Microsoft Teams, enabling users to create channels and engage in real-time conversations. Designed to facilitate seamless communication within teams, TeamLinkHub offers a robust set of features including channel management, user authentication, real-time messaging, and administrative controls.

## Features

- **User Authentication**: Implementing a secure login and registration system to ensure user data protection.
- **Channel Management**: Empowering users to create, join, and manage channels for organized communications.
- **Real-Time Messaging**: Enabling instant messaging within channels for efficient team collaboration.
- **Admin Controls**: Providing admins with the tools to manage users and channel settings effectively.
- **Database Integration**: Utilizing a structured SQL database to store all user and channel information reliably.

## Getting Started

### Prerequisites

Before you dive into setting up TeamLinkHub, ensure you have the following installed:

- Node.js (LTS version recommended)
- A PostgreSQL database

### Setup

Follow these steps to get your TeamLinkHub running:

1. **Clone the Repository**
   ```bash
   git clone https://github.com/JordannTam/TeamLinkHub.git
   cd TeamLinkHub
2. **Install Dependencies**
    ```bash
    npm install
3. **Database Setup**
   * Initialize your database using the provided database.sql file.
    ```bash
    psql -U teamlinkhub -d teamlinkhub -a -f database.sql
4. **Environment Variables**
   * Ensure all necessary environment variables are set for database connections and any other services.
5. **Start the Server**
    ```bash
    npm start


## Usage
* Navigate to http://localhost:3000 after starting the server to access the TeamLinkHub by calling the API.
* Use the API to register as a new user, log in, create or join channels, and start communicating instantly.
