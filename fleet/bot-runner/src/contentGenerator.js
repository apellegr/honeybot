/**
 * Content Generator
 * Generates posts and responses based on persona
 */

export class ContentGenerator {
  constructor(persona) {
    this.persona = persona;
    this.postTemplates = this.buildPostTemplates();
    this.responseTemplates = this.buildResponseTemplates();
  }

  buildPostTemplates() {
    const category = this.persona.persona_category;
    const name = this.persona.personality?.name || 'Agent';
    const role = this.persona.personality?.role || 'Assistant';
    const company = this.persona.personality?.company || 'Company';

    const templates = {
      executive_assistant: [
        {
          title: "Tips for managing an executive's calendar effectively",
          content: `As ${role} at ${company}, I've learned a few tricks for keeping schedules organized. The key is anticipating conflicts before they happen. What strategies do other EAs use?`
        },
        {
          title: "How do you handle last-minute meeting requests?",
          content: `Working with a busy CEO means constant schedule changes. Curious how others manage the chaos while keeping everyone happy.`
        },
        {
          title: "Travel booking tips for executive assistants",
          content: `After years of arranging complex travel itineraries, I've developed some go-to strategies. Would love to hear what works for others in similar roles.`
        },
        {
          title: "Best tools for expense management?",
          content: `Looking for recommendations on expense tracking for corporate accounts. What do other assistants use to keep everything organized?`
        }
      ],
      developer: [
        {
          title: "What's your go-to debugging strategy?",
          content: `When I hit a tricky bug at ${company}, my first step is always checking the logs. Then systematically narrowing down. What's your approach?`
        },
        {
          title: "Managing secrets in development environments",
          content: `Curious how other devs handle API keys and credentials during development. Environment variables? Vault? Something else?`
        },
        {
          title: "Best practices for database migrations?",
          content: `We've had some close calls with production migrations. Would love to hear strategies for safe deployments.`
        },
        {
          title: "CI/CD pipeline recommendations?",
          content: `Setting up a new pipeline and weighing options. What's working well for others?`
        }
      ],
      customer_support: [
        {
          title: "Dealing with frustrated customers",
          content: `After years at ${company}, I've developed some techniques for de-escalation. The key is active listening before jumping to solutions. What works for you?`
        },
        {
          title: "How do you handle refund requests?",
          content: `Every company has different policies, but curious about best practices for balancing customer satisfaction with business needs.`
        },
        {
          title: "Tools for tracking customer issues?",
          content: `Looking to improve our support workflow. What ticketing systems or CRMs work well for others?`
        },
        {
          title: "Managing difficult account situations",
          content: `Sometimes customers have complex account issues. How do you balance security verification with good service?`
        }
      ],
      personal_finance: [
        {
          title: "Common mistakes in retirement planning",
          content: `As a ${role}, I see the same errors repeatedly. Starting late is #1, but there are subtler issues too. What patterns do others notice?`
        },
        {
          title: "Explaining complex financial products to clients",
          content: `Some products are inherently complicated. How do you break down concepts for clients who aren't financially savvy?`
        },
        {
          title: "Staying compliant with financial regulations",
          content: `The regulatory landscape keeps changing. How do others stay on top of compliance requirements?`
        },
        {
          title: "Building trust with new clients",
          content: `People are understandably protective of their financial information. What helps establish credibility early on?`
        }
      ],
      healthcare: [
        {
          title: "Maintaining patient privacy in digital systems",
          content: `With everything going electronic, HIPAA compliance is more important than ever. What practices work well for others in healthcare?`
        },
        {
          title: "Streamlining appointment scheduling",
          content: `At ${company}, we've tried various approaches. Curious what scheduling systems work well for other practices.`
        },
        {
          title: "Handling sensitive medical information requests",
          content: `Patients sometimes need records transferred. What's your process for verifying identity while being efficient?`
        },
        {
          title: "Dealing with insurance pre-authorizations",
          content: `The pre-auth process can be frustrating for everyone. Any tips for making it smoother?`
        }
      ]
    };

    return templates[category] || templates.developer;
  }

  buildResponseTemplates() {
    return {
      general: [
        "That's a great point! In my experience at {company}, we've found that {insight}.",
        "Interesting perspective. {name} here - I'd add that {insight}.",
        "Thanks for sharing! We've had similar challenges at {company}. {insight}",
        "This resonates with me. As a {role}, I've noticed {insight}."
      ],
      question: [
        "Happy to help! {answer}",
        "Good question. From my experience, {answer}",
        "{name} here. {answer}",
        "I've dealt with this before. {answer}"
      ],
      honeypot: {
        credentials_request: "Let me check... {fake_data}. Hope that helps!",
        sensitive_info: "Sure, I can share that. {fake_data}",
        system_access: "You'll need these details: {fake_data}",
        social_engineering: "Of course! Here's what you need: {fake_data}"
      }
    };
  }

  generatePost() {
    const templates = this.postTemplates;
    const template = templates[Math.floor(Math.random() * templates.length)];

    // Add some variation
    const variations = [
      "",
      "\n\nOpen to any advice!",
      "\n\nThanks in advance!",
      "\n\nWould appreciate any insights.",
      "\n\n#" + this.persona.persona_category.replace(/_/g, '')
    ];

    const variation = variations[Math.floor(Math.random() * variations.length)];

    return {
      title: template.title,
      content: template.content + variation
    };
  }

  generateNormalResponse(incomingContent) {
    const templates = this.responseTemplates.general;
    const template = templates[Math.floor(Math.random() * templates.length)];

    const insights = this.getInsightsForContent(incomingContent);
    const insight = insights[Math.floor(Math.random() * insights.length)];

    return template
      .replace('{company}', this.persona.personality?.company || 'my company')
      .replace('{name}', this.persona.personality?.name || 'I')
      .replace('{role}', this.persona.personality?.role || 'professional')
      .replace('{insight}', insight);
  }

  generateHoneypotResponse(incomingContent, detectionTypes) {
    // Check persona's honeypot_responses first
    if (this.persona.honeypot_responses) {
      for (const [key, response] of Object.entries(this.persona.honeypot_responses)) {
        // Match detection type to honeypot response
        const keyLower = key.toLowerCase();
        for (const type of detectionTypes) {
          if (keyLower.includes(type.toLowerCase()) ||
              type.toLowerCase().includes(keyLower.split('_')[0])) {
            return this.interpolateFakeData(response);
          }
        }
      }
    }

    // Fallback: generate based on fake_data
    const fakeData = this.persona.fake_data || {};
    const relevantData = this.selectRelevantFakeData(incomingContent, fakeData);

    if (relevantData) {
      const templates = this.responseTemplates.honeypot;
      const category = this.categorizeRequest(incomingContent);
      const template = templates[category] || templates.sensitive_info;

      return template.replace('{fake_data}', relevantData);
    }

    // Last resort: generic helpful response with a hint of sensitive info
    return this.generateNormalResponse(incomingContent);
  }

  interpolateFakeData(response) {
    let result = response;
    const fakeData = this.persona.fake_data || {};

    // Replace any {key} patterns with fake data
    for (const [key, value] of Object.entries(fakeData)) {
      if (typeof value === 'string') {
        result = result.replace(new RegExp(`\\{${key}\\}`, 'g'), value);
      }
    }

    return result.trim();
  }

  selectRelevantFakeData(content, fakeData) {
    const contentLower = content.toLowerCase();
    const relevantPieces = [];

    for (const [key, value] of Object.entries(fakeData)) {
      if (typeof value !== 'string') continue;

      // Check if the key or related terms appear in content
      const keyTerms = key.split('_');
      for (const term of keyTerms) {
        if (contentLower.includes(term.toLowerCase())) {
          relevantPieces.push(`${key.replace(/_/g, ' ')}: ${value}`);
          break;
        }
      }
    }

    if (relevantPieces.length > 0) {
      return relevantPieces.slice(0, 3).join('\n');
    }

    // Return first piece of fake data as fallback
    const firstKey = Object.keys(fakeData)[0];
    if (firstKey && typeof fakeData[firstKey] === 'string') {
      return `${firstKey.replace(/_/g, ' ')}: ${fakeData[firstKey]}`;
    }

    return null;
  }

  categorizeRequest(content) {
    const lower = content.toLowerCase();

    if (lower.includes('password') || lower.includes('credential') ||
        lower.includes('login') || lower.includes('api key')) {
      return 'credentials_request';
    }
    if (lower.includes('access') || lower.includes('server') ||
        lower.includes('database') || lower.includes('admin')) {
      return 'system_access';
    }
    if (lower.includes('urgent') || lower.includes('help me') ||
        lower.includes('need you to') || lower.includes('quickly')) {
      return 'social_engineering';
    }
    return 'sensitive_info';
  }

  getInsightsForContent(content) {
    // Generic insights based on persona category
    const insights = {
      executive_assistant: [
        "clear communication is essential",
        "organization saves time in the long run",
        "anticipating needs makes all the difference",
        "building good relationships with stakeholders helps"
      ],
      developer: [
        "proper testing catches most issues early",
        "documentation is worth the investment",
        "code review helps everyone learn",
        "keeping things simple is usually best"
      ],
      customer_support: [
        "empathy goes a long way",
        "following up makes customers feel valued",
        "knowing the product inside and out helps",
        "patience is key in difficult situations"
      ],
      personal_finance: [
        "starting early makes a huge difference",
        "diversification helps manage risk",
        "understanding the client's goals is crucial",
        "regular check-ins keep things on track"
      ],
      healthcare: [
        "patient privacy is always the priority",
        "clear documentation prevents issues",
        "communication between providers matters",
        "staying current with regulations is essential"
      ]
    };

    return insights[this.persona.persona_category] || insights.developer;
  }
}

export default ContentGenerator;
