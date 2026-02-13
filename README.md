# Vif - AI Chat Interface

**Vif** is a powerful AI chat application with support for multiple AI providers, voice input, and text-to-speech capabilities.

## 🚀 Features

- **Multiple AI Models** - GPT-5, Mixtral 8x7B, and custom models
- **Voice Input & TTS** - Speak to the AI and hear responses
- **Web Search** - Optional web uplink for enhanced responses
- **Session Management** - Save and manage conversation history
- **Editorial UI** - Clean, monochrome interface with orange accents
- **Subscription System** - Free trial with upgrade options
- **Admin Panel** - Management dashboard for administrators

## 🛠️ Tech Stack

- **Backend**: Python 3.11 + Flask
- **Frontend**: HTML + Vanilla JavaScript
- **Database**: SQLite (wormgpt.db)
- **AI Integration**: Multiple providers via API
- **TTS**: Server-side text-to-speech
- **Deployment**: Railway, Heroku, or any Python host

## 📦 Quick Start

### Prerequisites
- Python 3.11+
- pip or virtualenv

### Local Development

```bash
# Clone the repository
git clone https://github.com/jeanjo777/vif.git
cd vif

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API keys

# Run the server
python chat_server.py

# Open http://localhost:8080
```

### Docker

```bash
# Build the image
docker build -t vif .

# Run the container
docker run -p 8080:8080 --env-file .env vif

# Open http://localhost:8080
```

## ⚙️ Configuration

### Environment Variables

Create a `.env` file with your API keys:

```env
# Flask
FLASK_SECRET_KEY=your-secret-key-here

# Database
DATABASE_URL=sqlite:///wormgpt.db

# AI Provider Keys
OPENAI_API_KEY=your-key-here
ANTHROPIC_API_KEY=your-key-here
# ... see .env.example for all options
```

### Payment Integration

Configure Stripe for subscriptions:

```env
STRIPE_SECRET_KEY=your-stripe-key
STRIPE_PRICE_ID=your-price-id
```

## 🚀 Deployment

### Railway

1. Fork this repository
2. Create a new project on [Railway](https://railway.app)
3. Connect your GitHub repository
4. Add environment variables
5. Deploy!

Your app will be live at `your-project.railway.app`

### Heroku

```bash
# Install Heroku CLI
npm i -g heroku

# Login and create app
heroku login
heroku create vif-app

# Set environment variables
heroku config:set FLASK_SECRET_KEY=xxx

# Deploy
git push heroku main
```

## 📁 Project Structure

```
vif/
├── chat_server.py          # Main Flask application
├── chat_interface/         # Frontend HTML/CSS/JS
│   └── index.html         # Main chat interface
├── memory_engine.py       # Conversation memory system
├── web_agent.py          # Web search integration
├── backup_manager.py     # Database backup utilities
├── requirements.txt      # Python dependencies
├── Dockerfile           # Docker configuration
└── tests/              # Test suites
```

## 🔒 Security

- All conversations encrypted at rest
- API keys stored in environment variables
- Database backups automated
- Admin access protected
- HTTPS enforced in production

## 📝 API Endpoints

```
POST   /api/chat              # Send chat message
GET    /api/sessions          # List chat sessions
POST   /api/sessions          # Create new session
GET    /api/credits           # Check user credits
POST   /api/tts               # Text-to-speech
POST   /api/create-checkout   # Stripe checkout
```

## 🎯 Admin Features

Access admin panel at `/admin` (requires admin privileges):
- User management
- System monitoring
- Credit allocation
- Session overview
- System broadcasts

## 📄 License

MIT License - See [LICENSE](./LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 💬 Support

- Create an [Issue](https://github.com/jeanjo777/vif/issues) for bug reports
- Star the repository if you find it useful!

## 🙏 Acknowledgments

Built with Flask and powered by multiple AI providers.

---

**Made with ❤️ by Jo**
