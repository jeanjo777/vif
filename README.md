# Vif

**Vif** - A powerful multimodal AI chat assistant with support for 19+ AI providers.

![Vif](./public/logo-dark-styled.svg)

## 🚀 Features

- **19+ AI Providers** - OpenRouter, Anthropic, OpenAI, Google, DeepSeek, and more
- **Multimodal Support** - Text, images, and files
- **Pure Conversational Interface** - Clean chat experience
- **Multi-Provider** - Switch between AI models seamlessly
- **History & Export** - Save and export your conversations
- **Voice Input** - Speech-to-text support
- **Dark/Light Mode** - Beautiful themes
- **Self-Hosted** - Deploy anywhere

## 🎯 Supported AI Providers

### Cloud Providers
- **OpenRouter** (Default) - Access to multiple models
- **Anthropic** - Claude models
- **OpenAI** - GPT models
- **Google** - Gemini
- **DeepSeek**
- **Groq**
- **Mistral**
- **Together AI**
- **X.AI** - Grok
- **Perplexity AI**
- **HuggingFace**
- **Cohere**
- **GitHub Models**
- **Amazon Bedrock**
- And more...

### Local Providers
- **Ollama** - Run models locally
- **LMStudio** - Local model management
- **OpenAI-compatible APIs**

## 🛠️ Tech Stack

- **Framework**: Remix + Vite
- **Language**: TypeScript
- **Styling**: UnoCSS + SCSS
- **AI SDK**: Vercel AI SDK
- **Database**: IndexedDB (local) + Supabase (optional)
- **Deployment**: Railway, Vercel, Netlify

## 📦 Quick Start

### Prerequisites
- Node.js 18+ or Docker
- pnpm (recommended) or npm

### Local Development

```bash
# Clone the repository
git clone https://github.com/jeanjo777/vif.git
cd vif

# Install dependencies
pnpm install

# Copy environment file
cp .env.example .env.local

# Add your API keys to .env.local
# At minimum, add one provider key (e.g., OPEN_ROUTER_API_KEY)

# Start development server
pnpm run dev

# Open http://localhost:5173
```

### Docker

```bash
# Build the image
pnpm run dockerbuild

# Run the container
pnpm run dockerrun

# Open http://localhost:5173
```

## ⚙️ Configuration

### Environment Variables

Create a `.env.local` file with your API keys:

```env
# OpenRouter (Recommended - gives access to multiple models)
OPEN_ROUTER_API_KEY=your_key_here

# Or use specific providers
ANTHROPIC_API_KEY=your_key_here
OPENAI_API_KEY=your_key_here
GOOGLE_GENERATIVE_AI_API_KEY=your_key_here

# Default provider
DEFAULT_PROVIDER=OpenRouter
```

See `.env.example` for all available configuration options.

## 🚀 Deployment

### Railway

1. Fork this repository
2. Create a new project on [Railway](https://railway.app)
3. Connect your GitHub repository
4. Add environment variables
5. Deploy!

Your app will be live at `your-project.railway.app`

### Vercel

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
pnpm run build
vercel --prod
```

### Netlify

```bash
# Install Netlify CLI
npm i -g netlify-cli

# Deploy
pnpm run build
netlify deploy --prod
```

## 📝 Scripts

```bash
pnpm run dev          # Start development server
pnpm run build        # Build for production
pnpm run start        # Start production server
pnpm run typecheck    # Run TypeScript checks
pnpm run lint         # Lint code
pnpm run lint:fix     # Fix linting issues
pnpm run test         # Run tests
```

## 🔒 Privacy

- All conversations are stored **locally** in your browser
- API keys are stored **locally** in cookies/localStorage
- Optional Supabase integration for cloud backup
- No data is sent to Vif servers (we don't have any!)

## 📄 License

MIT License - See [LICENSE](./LICENSE) for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 💬 Support

- Create an [Issue](https://github.com/jeanjo777/vif/issues) for bug reports
- Star the repository if you find it useful!

## 🙏 Acknowledgments

Built with modern web technologies and powered by the Vercel AI SDK.

---

**Made with ❤️ by the Vif team**
