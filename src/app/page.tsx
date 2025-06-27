// src/app/page.tsx
import Link from 'next/link';
import { Button } from '@/components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';

export default function HomePage() {
  const features = [
    {
      icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z',
      title: 'Advanced Analytics',
      description: 'Transform complex data into actionable insights with our comprehensive analytics suite designed specifically for consulting excellence.',
      color: 'from-primary to-accent'
    },
    {
      icon: 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z',
      title: 'Client Relationship Management',
      description: 'Build stronger client relationships with our integrated CRM platform that tracks every interaction and opportunity.',
      color: 'from-blue-500 to-blue-600'
    },
    {
      icon: 'M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z',
      title: 'Project Automation',
      description: 'Streamline workflows and eliminate repetitive tasks with intelligent automation that adapts to your consulting methodology.',
      color: 'from-emerald-500 to-emerald-600'
    },
    {
      icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
      title: 'Document Intelligence',
      description: 'Leverage AI-powered document analysis to extract insights and transform your consulting deliverables into strategic assets.',
      color: 'from-purple-500 to-purple-600'
    },
    {
      icon: 'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1',
      title: 'Financial Intelligence',
      description: 'Optimize profitability with comprehensive financial tracking, forecasting, and business intelligence capabilities.',
      color: 'from-orange-500 to-orange-600'
    },
    {
      icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
      title: 'Enterprise Security',
      description: 'Protect sensitive client information with bank-level security infrastructure and comprehensive compliance frameworks.',
      color: 'from-indigo-500 to-indigo-600'
    }
  ];

  const testimonials = [
    {
      quote: "InsightSerenity has revolutionized our client engagement process. The analytics capabilities have increased our project success rate by 45% while reducing delivery time significantly.",
      author: "Sarah Chen",
      title: "Managing Partner",
      company: "Strategic Advisors",
      avatar: "SC",
      color: 'from-primary to-accent'
    },
    {
      quote: "The platform's automation features have freed up our team to focus on high-value strategic work. Our client satisfaction scores have never been higher.",
      author: "Michael Rodriguez",
      title: "Principal",
      company: "Innovation Consulting",
      avatar: "MR",
      color: 'from-blue-500 to-blue-600'
    },
    {
      quote: "InsightSerenity's financial insights have helped us optimize our pricing strategy and improve margins by 30%. It's an essential tool for any serious consulting practice.",
      author: "Amanda Parker",
      title: "Director",
      company: "Growth Consulting",
      avatar: "AP",
      color: 'from-emerald-500 to-emerald-600'
    }
  ];

  const processSteps = [
    {
      step: '01',
      title: 'Strategic Assessment',
      description: 'Comprehensive analysis of your current consulting processes, client requirements, and growth objectives to design the optimal platform configuration.',
      icon: 'M9 5H7a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2zm8 0h-2a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2z'
    },
    {
      step: '02',
      title: 'Implementation & Training',
      description: 'Expert-led implementation with comprehensive team training, ensuring seamless adoption and maximum utilization of all platform capabilities.',
      icon: 'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253'
    },
    {
      step: '03',
      title: 'Integration & Optimization',
      description: 'Seamless integration with existing systems and continuous optimization to ensure peak performance and alignment with evolving business needs.',
      icon: 'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4'
    },
    {
      step: '04',
      title: 'Growth & Excellence',
      description: 'Ongoing support and platform evolution to drive continuous improvement, scalability, and competitive advantage in your market.',
      icon: 'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6'
    }
  ];

  const pricingPlans = [
    {
      name: 'Professional',
      price: '$99',
      period: 'per user/month',
      description: 'Perfect for growing consulting teams',
      features: [
        'Unlimited active projects',
        'Advanced analytics dashboard',
        'Client communication suite',
        'Custom workflow automation',
        'Priority support access',
        'API integration capability'
      ],
      popular: false,
      color: 'border-gray-200'
    },
    {
      name: 'Business Elite',
      price: '$199',
      period: 'per user/month',
      description: 'Ideal for established consulting practices',
      features: [
        'Everything in Professional',
        'Advanced financial intelligence',
        'Custom branding options',
        'Dedicated account management',
        'Advanced security features',
        'Custom integration support',
        'Performance optimization',
        'Strategic consulting sessions'
      ],
      popular: true,
      color: 'border-primary'
    },
    {
      name: 'Enterprise',
      price: 'Custom',
      period: 'tailored solutions',
      description: 'Comprehensive solutions for large organizations',
      features: [
        'Everything in Business Elite',
        'Custom platform development',
        'Enterprise-grade infrastructure',
        'Dedicated implementation team',
        'SLA guarantees',
        'Custom training programs',
        'White-label options',
        'Strategic partnership benefits'
      ],
      popular: false,
      color: 'border-gray-200'
    }
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Enhanced Navigation Header */}
      <header className="bg-surface/95 shadow-business border-b border-border sticky top-0 z-50 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-18">
            <div className="flex items-center">
              <h1 className="text-2xl font-bold text-gradient-gold">
                InsightSerenity
              </h1>
            </div>
            
            {/* Centered Navigation */}
            <nav className="hidden lg:flex items-center space-x-12">
              <a href="#features" className="text-text-secondary hover:text-primary font-semibold transition-all duration-300 relative group">
                Features
                <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-primary transition-all duration-300 group-hover:w-full"></span>
              </a>
              <a href="#solutions" className="text-text-secondary hover:text-primary font-semibold transition-all duration-300 relative group">
                Solutions
                <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-primary transition-all duration-300 group-hover:w-full"></span>
              </a>
              <a href="#pricing" className="text-text-secondary hover:text-primary font-semibold transition-all duration-300 relative group">
                Pricing
                <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-primary transition-all duration-300 group-hover:w-full"></span>
              </a>
              <a href="#about" className="text-text-secondary hover:text-primary font-semibold transition-all duration-300 relative group">
                About
                <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-primary transition-all duration-300 group-hover:w-full"></span>
              </a>
            </nav>

            {/* Authentication Buttons */}
            <div className="flex items-center space-x-4">
              <Link href="/auth/login">
                <Button variant="ghost" size="sm" className="font-semibold">
                  Sign In
                </Button>
              </Link>
              <Link href="/auth/register">
                <Button variant="primary" size="sm" className="font-semibold">
                  Get Started
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section with Enhanced Visual Appeal */}
      <section className="relative bg-gradient-to-br from-background via-surface to-gold-50/30 py-28 lg:py-36 overflow-hidden">
        {/* Enhanced Background Elements */}
        <div className="absolute inset-0 bg-dot-pattern opacity-20"></div>
        <div className="absolute top-20 right-20 w-96 h-96 bg-gradient-to-br from-primary/20 to-accent/20 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-20 left-20 w-80 h-80 bg-gradient-to-tr from-secondary/5 to-secondary-light/5 rounded-full blur-3xl"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-primary/5 to-transparent rounded-full blur-3xl"></div>
        
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center animate-fade-up">
            <div className="mb-6">
              <span className="inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold bg-primary/10 text-primary border border-primary/20">
                <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" clipRule="evenodd" />
                </svg>
                Trusted by 500+ Consulting Firms Worldwide
              </span>
            </div>
            
            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold text-text-primary mb-8 leading-tight">
              Transform Your{' '}
              <span className="text-gradient-gold relative">
                Consulting Practice
                <svg className="absolute -bottom-2 left-0 w-full h-3 text-primary/30" viewBox="0 0 300 12" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M1 6C50 1 100 1 150 6C200 11 250 11 299 6" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
                </svg>
              </span>
              <br />
              with Advanced Intelligence
            </h1>
            
            <p className="text-xl text-text-secondary mb-12 max-w-4xl mx-auto leading-relaxed">
              InsightSerenity empowers consulting professionals with cutting-edge analytics, seamless client management, and intelligent automation to deliver exceptional results and accelerate sustainable business growth.
            </p>
            
            <div className="flex flex-col sm:flex-row gap-6 justify-center mb-16">
              <Link href="/auth/register">
                <Button variant="primary" size="xl" className="min-w-64 animate-pulse-gold">
                  Start Free Trial
                  <svg className="ml-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                </Button>
              </Link>
              <Button variant="outline" size="xl" className="min-w-64 group">
                Schedule Demo
                <svg className="ml-2 h-5 w-5 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
                </svg>
              </Button>
            </div>
            
            {/* Enhanced Trust Indicators */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-8 max-w-4xl mx-auto text-text-muted">
              <div className="flex items-center justify-center space-x-3">
                <div className="h-8 w-8 bg-emerald-100 rounded-full flex items-center justify-center">
                  <svg className="h-4 w-4 text-emerald-600" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                </div>
                <span className="font-semibold">14-day free trial</span>
              </div>
              <div className="flex items-center justify-center space-x-3">
                <div className="h-8 w-8 bg-blue-100 rounded-full flex items-center justify-center">
                  <svg className="h-4 w-4 text-blue-600" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                </div>
                <span className="font-semibold">No credit card required</span>
              </div>
              <div className="flex items-center justify-center space-x-3">
                <div className="h-8 w-8 bg-purple-100 rounded-full flex items-center justify-center">
                  <svg className="h-4 w-4 text-purple-600" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                </div>
                <span className="font-semibold">24/7 expert support</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Enhanced Stats Section */}
      <section className="py-20 bg-gradient-to-r from-secondary via-secondary-light to-secondary relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-10"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-12 text-center">
            <div className="animate-fade-up group">
              <div className="text-5xl font-bold text-primary mb-3 group-hover:scale-110 transition-transform duration-300">500+</div>
              <div className="text-text-inverse font-semibold text-lg">Consulting Firms</div>
              <div className="text-gray-400 text-sm mt-1">Trust our platform</div>
            </div>
            <div className="animate-fade-up group" style={{ animationDelay: '0.1s' }}>
              <div className="text-5xl font-bold text-primary mb-3 group-hover:scale-110 transition-transform duration-300">2.5M+</div>
              <div className="text-text-inverse font-semibold text-lg">Projects Managed</div>
              <div className="text-gray-400 text-sm mt-1">Successfully completed</div>
            </div>
            <div className="animate-fade-up group" style={{ animationDelay: '0.2s' }}>
              <div className="text-5xl font-bold text-primary mb-3 group-hover:scale-110 transition-transform duration-300">98%</div>
              <div className="text-text-inverse font-semibold text-lg">Client Satisfaction</div>
              <div className="text-gray-400 text-sm mt-1">Average rating</div>
            </div>
            <div className="animate-fade-up group" style={{ animationDelay: '0.3s' }}>
              <div className="text-5xl font-bold text-primary mb-3 group-hover:scale-110 transition-transform duration-300">40%</div>
              <div className="text-text-inverse font-semibold text-lg">Productivity Increase</div>
              <div className="text-gray-400 text-sm mt-1">On average</div>
            </div>
          </div>
        </div>
      </section>

      {/* Enhanced Features Section */}
      <section id="features" className="py-24 bg-surface relative">
        <div className="absolute inset-0 bg-dot-pattern opacity-5"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20 animate-fade-up">
            <div className="mb-4">
              <span className="inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold bg-primary/10 text-primary border border-primary/20">
                Platform Capabilities
              </span>
            </div>
            <h2 className="text-4xl lg:text-5xl font-bold text-text-primary mb-6">
              Comprehensive Tools for{' '}
              <span className="text-gradient-gold">Consulting Excellence</span>
            </h2>
            <p className="text-xl text-text-secondary max-w-4xl mx-auto leading-relaxed">
              Everything you need to manage clients, projects, and growth in one powerful platform designed specifically for consulting professionals who demand excellence.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {features.map((feature, index) => (
              <Card key={index} variant="premium" className="animate-fade-up group hover:scale-105 transition-all duration-500" style={{ animationDelay: `${index * 0.1}s` }}>
                <CardContent>
                  <div className={`h-14 w-14 bg-gradient-to-r ${feature.color} rounded-xl flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-300`}>
                    <svg className="h-7 w-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={feature.icon} />
                    </svg>
                  </div>
                  <h3 className="text-xl font-bold text-text-primary mb-3">{feature.title}</h3>
                  <p className="text-text-secondary leading-relaxed">
                    {feature.description}
                  </p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Enhanced Solutions Section */}
      <section id="solutions" className="py-24 bg-gradient-to-br from-background to-gold-50/20 relative overflow-hidden">
        <div className="absolute top-20 right-20 w-64 h-64 bg-gradient-to-br from-primary/10 to-accent/10 rounded-full blur-3xl"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20 animate-fade-up">
            <div className="mb-4">
              <span className="inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold bg-primary/10 text-primary border border-primary/20">
                Implementation Process
              </span>
            </div>
            <h2 className="text-4xl lg:text-5xl font-bold text-text-primary mb-6">
              How InsightSerenity{' '}
              <span className="text-gradient-gold">Transforms</span> Your Practice
            </h2>
            <p className="text-xl text-text-secondary max-w-4xl mx-auto leading-relaxed">
              Our proven methodology ensures your consulting practice realizes value quickly while building the foundation for sustained competitive advantage.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {processSteps.map((step, index) => (
              <div key={index} className="relative animate-fade-up" style={{ animationDelay: `${index * 0.15}s` }}>
                <div className="flex flex-col items-center text-center group">
                  <div className="relative mb-6">
                    <div className="w-20 h-20 bg-gradient-to-r from-primary to-accent rounded-2xl flex items-center justify-center text-secondary font-bold text-xl shadow-business-lg group-hover:scale-110 transition-transform duration-300">
                      {step.step}
                    </div>
                    <div className="absolute -inset-2 bg-gradient-to-r from-primary/20 to-accent/20 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 blur-lg"></div>
                  </div>
                  <div className="mb-4 h-12 w-12 bg-gradient-to-r from-primary/10 to-accent/10 rounded-lg flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                    <svg className="h-6 w-6 text-primary" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={step.icon} />
                    </svg>
                  </div>
                  <h3 className="text-xl font-bold text-text-primary mb-3">{step.title}</h3>
                  <p className="text-text-secondary leading-relaxed">{step.description}</p>
                </div>
                {index < processSteps.length - 1 && (
                  <div className="hidden lg:block absolute top-10 left-full w-full h-0.5 bg-gradient-to-r from-primary to-accent transform -translate-x-8 opacity-30" />
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Enhanced Testimonials Section */}
      <section className="py-24 bg-surface relative">
        <div className="absolute inset-0 bg-dot-pattern opacity-5"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20 animate-fade-up">
            <div className="mb-4">
              <span className="inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold bg-primary/10 text-primary border border-primary/20">
                Client Success Stories
              </span>
            </div>
            <h2 className="text-4xl lg:text-5xl font-bold text-text-primary mb-6">
              Trusted by Leading{' '}
              <span className="text-gradient-gold">Consulting Professionals</span>
            </h2>
            <p className="text-xl text-text-secondary max-w-4xl mx-auto leading-relaxed">
              Discover how InsightSerenity has transformed consulting practices across industries and geographies, delivering measurable results and competitive advantages.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {testimonials.map((testimonial, index) => (
              <Card key={index} variant="glass" className="animate-fade-up group hover:scale-105 transition-all duration-500" style={{ animationDelay: `${index * 0.1}s` }}>
                <CardContent>
                  <div className="flex items-center mb-6">
                    <div className="flex space-x-1">
                      {[...Array(5)].map((_, i) => (
                        <svg key={i} className="h-5 w-5 text-primary" fill="currentColor" viewBox="0 0 20 20">
                          <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" />
                        </svg>
                      ))}
                    </div>
                  </div>
                  <p className="text-text-secondary mb-6 italic text-lg leading-relaxed">
                    "{testimonial.quote}"
                  </p>
                  <div className="flex items-center">
                    <div className={`h-12 w-12 bg-gradient-to-r ${testimonial.color} rounded-full flex items-center justify-center text-white font-bold text-sm group-hover:scale-110 transition-transform duration-300`}>
                      {testimonial.avatar}
                    </div>
                    <div className="ml-4">
                      <p className="font-bold text-text-primary">{testimonial.author}</p>
                      <p className="text-sm text-text-secondary">{testimonial.title}</p>
                      <p className="text-sm text-primary font-semibold">{testimonial.company}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Enhanced Pricing Section */}
      <section id="pricing" className="py-24 bg-gradient-to-br from-background to-gold-50/20 relative overflow-hidden">
        <div className="absolute bottom-20 left-20 w-64 h-64 bg-gradient-to-br from-primary/10 to-accent/10 rounded-full blur-3xl"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-20 animate-fade-up">
            <div className="mb-4">
              <span className="inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold bg-primary/10 text-primary border border-primary/20">
                Flexible Investment Options
              </span>
            </div>
            <h2 className="text-4xl lg:text-5xl font-bold text-text-primary mb-6">
              Choose Your{' '}
              <span className="text-gradient-gold">Success</span> Plan
            </h2>
            <p className="text-xl text-text-secondary max-w-4xl mx-auto leading-relaxed">
              Flexible pricing options designed to grow with your consulting practice. Start with our comprehensive trial and scale as your success demands evolve.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {pricingPlans.map((plan, index) => (
              <Card key={index} className={`relative ${plan.popular ? 'scale-105 shadow-business-xl' : ''} animate-fade-up group hover:scale-105 transition-all duration-500`} style={{ animationDelay: `${index * 0.1}s` }}>
                {plan.popular && (
                  <div className="absolute -top-4 left-1/2 transform -translate-x-1/2">
                    <span className="bg-gradient-to-r from-primary to-accent text-secondary px-6 py-2 rounded-full text-sm font-bold shadow-business">
                      Most Popular Choice
                    </span>
                  </div>
                )}
                <CardContent className="p-8">
                  <div className="text-center mb-8">
                    <h3 className="text-2xl font-bold text-text-primary mb-2">{plan.name}</h3>
                    <div className="mb-4">
                      <span className="text-5xl font-bold text-text-primary">{plan.price}</span>
                      {plan.price !== 'Custom' && (
                        <span className="text-text-secondary ml-2">{plan.period}</span>
                      )}
                      {plan.price === 'Custom' && (
                        <span className="text-text-secondary ml-2 block text-lg">{plan.period}</span>
                      )}
                    </div>
                    <p className="text-text-secondary leading-relaxed">{plan.description}</p>
                  </div>
                  
                  <ul className="space-y-4 mb-8">
                    {plan.features.map((feature, featureIndex) => (
                      <li key={featureIndex} className="flex items-start">
                        <div className="h-5 w-5 bg-emerald-100 rounded-full flex items-center justify-center mr-3 mt-0.5 flex-shrink-0">
                          <svg className="h-3 w-3 text-emerald-600" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                          </svg>
                        </div>
                        <span className="text-text-secondary">{feature}</span>
                      </li>
                    ))}
                  </ul>
                  
                  <Button 
                    className="w-full group"
                    variant={plan.popular ? 'primary' : 'outline'}
                    size="lg"
                  >
                    {plan.price === 'Custom' ? 'Contact Sales' : 'Start Free Trial'}
                    <svg className="ml-2 h-4 w-4 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="py-24 bg-surface relative">
        <div className="absolute inset-0 bg-dot-pattern opacity-5"></div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <div className="animate-fade-up">
              <div className="mb-4">
                <span className="inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold bg-primary/10 text-primary border border-primary/20">
                  About InsightSerenity
                </span>
              </div>
              <h2 className="text-4xl lg:text-5xl font-bold text-text-primary mb-6">
                Built by Consultants,{' '}
                <span className="text-gradient-gold">for Consultants</span>
              </h2>
              <p className="text-xl text-text-secondary mb-8 leading-relaxed">
                InsightSerenity was founded by experienced consulting professionals who understood the unique challenges of scaling a successful practice. We've built the platform we always wished we had.
              </p>
              <div className="space-y-6 mb-8">
                <div className="flex items-start space-x-4">
                  <div className="h-8 w-8 bg-primary rounded-lg flex items-center justify-center flex-shrink-0">
                    <svg className="h-4 w-4 text-secondary" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-bold text-text-primary mb-1">Industry Expertise</h3>
                    <p className="text-text-secondary">Deep understanding of consulting workflows and client management needs.</p>
                  </div>
                </div>
                <div className="flex items-start space-x-4">
                  <div className="h-8 w-8 bg-primary rounded-lg flex items-center justify-center flex-shrink-0">
                    <svg className="h-4 w-4 text-secondary" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-bold text-text-primary mb-1">Continuous Innovation</h3>
                    <p className="text-text-secondary">Regular platform updates based on real consulting practice feedback.</p>
                  </div>
                </div>
                <div className="flex items-start space-x-4">
                  <div className="h-8 w-8 bg-primary rounded-lg flex items-center justify-center flex-shrink-0">
                    <svg className="h-4 w-4 text-secondary" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  </div>
                  <div>
                    <h3 className="font-bold text-text-primary mb-1">Dedicated Support</h3>
                    <p className="text-text-secondary">24/7 support from professionals who understand your business challenges.</p>
                  </div>
                </div>
              </div>
            </div>
            <div className="animate-fade-up" style={{ animationDelay: '0.2s' }}>
              <div className="relative">
                <div className="bg-gradient-to-br from-primary/20 to-accent/20 rounded-2xl p-8 backdrop-blur-sm border border-primary/20">
                  <div className="grid grid-cols-2 gap-6">
                    <div className="text-center">
                      <div className="text-3xl font-bold text-primary mb-2">10+</div>
                      <div className="text-sm text-text-secondary">Years Experience</div>
                    </div>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-primary mb-2">500+</div>
                      <div className="text-sm text-text-secondary">Happy Clients</div>
                    </div>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-primary mb-2">50+</div>
                      <div className="text-sm text-text-secondary">Team Members</div>
                    </div>
                    <div className="text-center">
                      <div className="text-3xl font-bold text-primary mb-2">24/7</div>
                      <div className="text-sm text-text-secondary">Support Available</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Enhanced CTA Section - Keeping the Content You Love */}
      <section className="py-24 bg-gradient-to-r from-secondary via-secondary-light to-secondary relative overflow-hidden">
        <div className="absolute inset-0 bg-grid-pattern opacity-10"></div>
        <div className="relative max-w-5xl mx-auto text-center px-4 sm:px-6 lg:px-8 animate-fade-up">
          <div className="mb-6">
            <span className="inline-flex items-center px-4 py-2 rounded-full text-sm font-semibold bg-primary/20 text-primary border border-primary/30">
              <svg className="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.915c.969 0 1.371 1.24.588 1.81l-3.976 2.888a1 1 0 00-.363 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.976-2.888a1 1 0 00-1.176 0l-3.976 2.888c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.363-1.118l-3.976-2.888c-.784-.57-.38-1.81.588-1.81h4.914a1 1 0 00.951-.69l1.519-4.674z" clipRule="evenodd" />
              </svg>
              Join the Success Stories
            </span>
          </div>
          <h2 className="text-4xl lg:text-5xl font-bold text-text-inverse mb-6">
            Ready to Transform Your{' '}
            <span className="text-primary">Consulting Practice?</span>
          </h2>
          <p className="text-xl text-gray-300 mb-10 leading-relaxed max-w-3xl mx-auto">
            Join thousands of consulting professionals who have already elevated their practice with InsightSerenity.
          </p>
          <div className="flex flex-col sm:flex-row gap-6 justify-center mb-8">
            <Link href="/auth/register">
              <Button variant="primary" size="xl" className="min-w-64 animate-pulse-gold">
                Start Your Free Trial
                <svg className="ml-2 h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                </svg>
              </Button>
            </Link>
            <Button variant="outline" size="xl" className="min-w-64 border-gray-400 text-gray-300 hover:bg-gray-400 hover:text-secondary group">
              Schedule Consultation
              <svg className="ml-2 h-5 w-5 transition-transform group-hover:translate-x-1" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
            </Button>
          </div>
          <p className="text-sm text-gray-400">
            No credit card required • 14-day free trial • Cancel anytime
          </p>
        </div>
      </section>

      {/* Enhanced Footer */}
      <footer className="bg-surface border-t border-border py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-12">
            <div className="col-span-1 md:col-span-2">
              <h3 className="text-2xl font-bold text-gradient-gold mb-6">InsightSerenity</h3>
              <p className="text-text-secondary mb-6 max-w-md leading-relaxed">
                Empowering consulting professionals with intelligent tools and insights to deliver exceptional results and drive sustainable business growth across all industries.
              </p>
              <div className="flex space-x-6">
                <a href="#" className="text-text-muted hover:text-primary transition-colors duration-300 transform hover:scale-110">
                  <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M24 4.557c-.883.392-1.832.656-2.828.775 1.017-.609 1.798-1.574 2.165-2.724-.951.564-2.005.974-3.127 1.195-.897-.957-2.178-1.555-3.594-1.555-3.179 0-5.515 2.966-4.797 6.045-4.091-.205-7.719-2.165-10.148-5.144-1.29 2.213-.669 5.108 1.523 6.574-.806-.026-1.566-.247-2.229-.616-.054 2.281 1.581 4.415 3.949 4.89-.693.188-1.452.232-2.224.084.626 1.956 2.444 3.379 4.6 3.419-2.07 1.623-4.678 2.348-7.29 2.04 2.179 1.397 4.768 2.212 7.548 2.212 9.142 0 14.307-7.721 13.995-14.646.962-.695 1.797-1.562 2.457-2.549z"/>
                  </svg>
                </a>
                <a href="#" className="text-text-muted hover:text-primary transition-colors duration-300 transform hover:scale-110">
                  <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                  </svg>
                </a>
                <a href="#" className="text-text-muted hover:text-primary transition-colors duration-300 transform hover:scale-110">
                  <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M12.017 0C5.396 0 .029 5.367.029 11.987c0 5.079 3.158 9.417 7.618 11.174-.105-.949-.199-2.403.041-3.439.219-.937 1.406-5.957 1.406-5.957s-.359-.72-.359-1.781c0-1.663.967-2.911 2.168-2.911 1.024 0 1.518.769 1.518 1.688 0 1.029-.653 2.567-.992 3.992-.285 1.193.6 2.165 1.775 2.165 2.128 0 3.768-2.245 3.768-5.487 0-2.861-2.063-4.869-5.008-4.869-3.41 0-5.409 2.562-5.409 5.199 0 1.033.394 2.143.889 2.741.099.12.112.225.085.345-.09.375-.293 1.199-.334 1.363-.053.225-.172.271-.402.165-1.495-.69-2.433-2.878-2.433-4.646 0-3.776 2.748-7.252 7.92-7.252 4.158 0 7.392 2.967 7.392 6.923 0 4.135-2.607 7.462-6.233 7.462-1.214 0-2.357-.629-2.754-1.378l-.748 2.853c-.271 1.043-1.002 2.35-1.492 3.146C9.57 23.812 10.763 24.009 12.017 24.009c6.624 0 11.99-5.367 11.99-11.988C24.007 5.367 18.641.001 12.017.001z"/>
                  </svg>
                </a>
              </div>
            </div>
            
            <div>
              <h4 className="font-bold text-text-primary mb-6">Product</h4>
              <ul className="space-y-3">
                <li><a href="#features" className="text-text-secondary hover:text-primary transition-colors duration-300">Features</a></li>
                <li><a href="#pricing" className="text-text-secondary hover:text-primary transition-colors duration-300">Pricing</a></li>
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">Security</a></li>
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">Integrations</a></li>
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">API</a></li>
              </ul>
            </div>
            
            <div>
              <h4 className="font-bold text-text-primary mb-6">Support</h4>
              <ul className="space-y-3">
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">Documentation</a></li>
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">Help Center</a></li>
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">Contact</a></li>
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">Status</a></li>
                <li><a href="#" className="text-text-secondary hover:text-primary transition-colors duration-300">Community</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-border mt-16 pt-8 flex flex-col md:flex-row justify-between items-center">
            <p className="text-text-muted text-sm">
              © 2025 InsightSerenity. All rights reserved. Built for consulting excellence.
            </p>
            <div className="flex space-x-8 mt-4 md:mt-0">
              <a href="#" className="text-text-muted hover:text-primary text-sm transition-colors duration-300">Privacy Policy</a>
              <a href="#" className="text-text-muted hover:text-primary text-sm transition-colors duration-300">Terms of Service</a>
              <a href="#" className="text-text-muted hover:text-primary text-sm transition-colors duration-300">Cookie Policy</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}