// src/app/page.tsx
import Link from 'next/link';
import { Button } from '@/components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '@/components/ui/Card';

export default function HomePage() {
  const features = [
    {
      icon: '🎯',
      title: 'Strategic Planning',
      description: 'Develop and execute comprehensive strategies with our advanced planning tools and frameworks.'
    },
    {
      icon: '📊',
      title: 'Analytics & Insights',
      description: 'Transform data into actionable insights with our powerful analytics and reporting capabilities.'
    },
    {
      icon: '👥',
      title: 'Client Management',
      description: 'Manage client relationships effectively with integrated CRM and communication tools.'
    },
    {
      icon: '🔄',
      title: 'Process Optimization',
      description: 'Streamline operations and improve efficiency with automated workflows and best practices.'
    },
    {
      icon: '📈',
      title: 'Performance Tracking',
      description: 'Monitor key performance indicators and track progress toward strategic objectives.'
    },
    {
      icon: '🤝',
      title: 'Collaboration Tools',
      description: 'Foster team collaboration with integrated communication and project management features.'
    },
    {
      icon: '🛡️',
      title: 'Security & Compliance',
      description: 'Ensure data security and regulatory compliance with enterprise-grade protection.'
    },
    {
      icon: '⚡',
      title: 'Rapid Implementation',
      description: 'Get up and running quickly with our streamlined onboarding and setup process.'
    }
  ];

  const testimonials = [
    {
      quote: "InsightSerenity has transformed how we deliver value to our clients. Our project efficiency has improved by 45% since implementation.",
      author: "Sarah Chen",
      title: "Managing Partner",
      company: "Strategic Insights Group"
    },
    {
      quote: "The platform's analytics capabilities have given us unprecedented visibility into our business performance and client satisfaction metrics.",
      author: "Michael Rodriguez",
      title: "Director of Operations", 
      company: "Innovation Consulting LLC"
    },
    {
      quote: "Our team productivity has increased significantly. The integrated workflow tools have eliminated countless hours of administrative work.",
      author: "Emily Thompson",
      title: "Senior Consultant",
      company: "Business Transformation Partners"
    }
  ];

  const processSteps = [
    {
      step: '01',
      title: 'Assessment & Setup',
      description: 'We analyze your current processes and configure the platform to match your specific consulting methodology and client requirements.'
    },
    {
      step: '02', 
      title: 'Team Onboarding',
      description: 'Your team receives comprehensive training and support to ensure smooth adoption and maximum utilization of all platform features.'
    },
    {
      step: '03',
      title: 'Implementation & Integration',
      description: 'We integrate with your existing tools and systems, ensuring seamless data flow and minimal disruption to ongoing projects.'
    },
    {
      step: '04',
      title: 'Optimization & Growth',
      description: 'Continuous monitoring and optimization ensure your consulting practice evolves with changing market demands and opportunities.'
    }
  ];

  const stats = [
    { value: '2,500+', label: 'Consulting Firms' },
    { value: '150,000+', label: 'Projects Managed' },
    { value: '99.9%', label: 'Uptime Guarantee' },
    { value: '40%', label: 'Average Efficiency Gain' }
  ];

  const pricingPlans = [
    {
      name: 'Starter',
      price: '$49',
      period: 'per user/month',
      description: 'Perfect for small consulting teams getting started',
      features: [
        'Up to 5 active projects',
        'Basic analytics and reporting',
        'Client communication tools',
        'Standard support'
      ]
    },
    {
      name: 'Professional',
      price: '$99',
      period: 'per user/month',
      description: 'Ideal for growing consulting practices',
      features: [
        'Unlimited projects',
        'Advanced analytics and insights',
        'Custom workflow automation',
        'Priority support',
        'API access'
      ],
      popular: true
    },
    {
      name: 'Enterprise',
      price: 'Custom',
      period: 'contact for pricing',
      description: 'Tailored solutions for large organizations',
      features: [
        'Custom integrations',
        'Dedicated account manager',
        'Advanced security features',
        'SLA guarantees',
        'Custom training programs'
      ]
    }
  ];

  const faqs = [
    {
      question: 'How quickly can we implement InsightSerenity in our consulting practice?',
      answer: 'Most consulting firms are fully operational within 2-4 weeks. Our implementation timeline depends on the complexity of your requirements and existing systems integration needs.'
    },
    {
      question: 'Does InsightSerenity integrate with our existing tools and systems?',
      answer: 'Yes, we offer robust integration capabilities with popular business tools including CRM systems, accounting software, project management platforms, and communication tools.'
    },
    {
      question: 'What level of support is available during implementation and ongoing use?',
      answer: 'We provide comprehensive support including dedicated implementation specialists, ongoing technical support, training resources, and regular check-ins to ensure optimal platform utilization.'
    },
    {
      question: 'Is my data secure and compliant with industry regulations?',
      answer: 'Absolutely. We maintain enterprise-grade security standards with SOC 2 Type II compliance, GDPR compliance, and regular security audits to protect your sensitive business information.'
    },
    {
      question: 'Can the platform scale as our consulting practice grows?',
      answer: 'InsightSerenity is designed to scale with your business. Our flexible architecture accommodates growth from small teams to large enterprise consulting organizations.'
    }
  ];

  return (
    <div className="min-h-screen">
      {/* Navigation Header */}
      <nav className="fixed top-0 w-full bg-white/95 backdrop-blur-md border-b border-gray-100 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center">
              <h1 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                InsightSerenity
              </h1>
            </div>
            <div className="hidden md:flex items-center space-x-8">
              <Link href="#features" className="text-sm text-gray-700 hover:text-gray-900 transition-colors">
                Features
              </Link>
              <Link href="#solutions" className="text-sm text-gray-700 hover:text-gray-900 transition-colors">
                Solutions
              </Link>
              <Link href="#pricing" className="text-sm text-gray-700 hover:text-gray-900 transition-colors">
                Pricing
              </Link>
              <Link href="#about" className="text-sm text-gray-700 hover:text-gray-900 transition-colors">
                About
              </Link>
            </div>
            <div className="flex items-center space-x-4">
              <Link href="/auth/login">
                <Button variant="ghost" size="sm">
                  Sign in
                </Button>
              </Link>
              <Link href="/auth/register">
                <Button size="sm">
                  Get Started
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4 sm:px-6 lg:px-8 bg-gradient-to-br from-gray-50 via-white to-blue-50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center">
            <h2 className="text-5xl sm:text-6xl font-bold text-gray-900 leading-tight">
              Transform Your Business with
              <span className="block bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                Intelligent Consulting Solutions
              </span>
            </h2>
            <p className="mt-6 text-lg text-gray-600 max-w-3xl mx-auto">
              Streamline operations, optimize performance, and accelerate growth with our comprehensive platform designed for modern consulting firms. Transform data into insights, insights into strategy, and strategy into results.
            </p>
            <div className="mt-10 flex flex-col sm:flex-row gap-4 justify-center">
              <Link href="/auth/register">
                <Button size="lg" className="px-8 py-3">
                  Start Free Trial
                </Button>
              </Link>
              <Button variant="outline" size="lg" className="px-8 py-3">
                Schedule Demo
              </Button>
            </div>
            <p className="mt-4 text-sm text-gray-500">
              Free 14-day trial • No credit card required • Enterprise-grade security
            </p>
          </div>
        </div>
      </section>

      {/* Statistics Section */}
      <section className="py-16 px-4 sm:px-6 lg:px-8 bg-white">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-12">
            <h3 className="text-3xl font-bold text-gray-900 mb-4">
              Trusted by Leading Consulting Firms Worldwide
            </h3>
            <p className="text-lg text-gray-600">
              Join thousands of consultants who have transformed their practices with InsightSerenity
            </p>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat, index) => (
              <div key={index} className="text-center">
                <div className="text-4xl font-bold text-blue-600 mb-2">{stat.value}</div>
                <div className="text-gray-600">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 sm:px-6 lg:px-8 bg-gray-50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h3 className="text-4xl font-bold text-gray-900 mb-4">
              Comprehensive Tools for Modern Consulting
            </h3>
            <p className="text-lg text-gray-600 max-w-3xl mx-auto">
              Our integrated platform provides everything you need to deliver exceptional results for your clients while growing your practice efficiently.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <Card key={index} className="hover:shadow-lg transition-shadow">
                <CardContent className="p-6">
                  <div className="w-12 h-12 bg-gradient-to-r from-blue-500 to-indigo-500 rounded-lg flex items-center justify-center mb-4 text-2xl">
                    {feature.icon}
                  </div>
                  <h4 className="text-lg font-semibold text-gray-900 mb-2">{feature.title}</h4>
                  <p className="text-sm text-gray-600">{feature.description}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works Section */}
      <section id="solutions" className="py-20 px-4 sm:px-6 lg:px-8 bg-white">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h3 className="text-4xl font-bold text-gray-900 mb-4">
              How InsightSerenity Works
            </h3>
            <p className="text-lg text-gray-600 max-w-3xl mx-auto">
              Our proven implementation methodology ensures your consulting practice realizes value quickly and scales effectively.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {processSteps.map((step, index) => (
              <div key={index} className="relative">
                <div className="flex flex-col items-center text-center">
                  <div className="w-16 h-16 bg-gradient-to-r from-blue-600 to-indigo-600 rounded-full flex items-center justify-center text-white font-bold text-lg mb-4">
                    {step.step}
                  </div>
                  <h4 className="text-xl font-semibold text-gray-900 mb-2">{step.title}</h4>
                  <p className="text-gray-600">{step.description}</p>
                </div>
                {index < processSteps.length - 1 && (
                  <div className="hidden lg:block absolute top-8 left-full w-full h-0.5 bg-gradient-to-r from-blue-600 to-indigo-600 transform -translate-x-8" />
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Testimonials Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-gray-50">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h3 className="text-4xl font-bold text-gray-900 mb-4">
              What Our Clients Say
            </h3>
            <p className="text-lg text-gray-600">
              Hear from consulting professionals who have transformed their practices with InsightSerenity
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {testimonials.map((testimonial, index) => (
              <Card key={index} className="bg-white">
                <CardContent className="p-6">
                  <div className="text-4xl text-blue-600 mb-4">"</div>
                  <p className="text-gray-700 mb-6 italic">{testimonial.quote}</p>
                  <div className="border-t pt-4">
                    <p className="font-semibold text-gray-900">{testimonial.author}</p>
                    <p className="text-sm text-gray-600">{testimonial.title}</p>
                    <p className="text-sm text-blue-600">{testimonial.company}</p>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing Section */}
      <section id="pricing" className="py-20 px-4 sm:px-6 lg:px-8 bg-white">
        <div className="max-w-7xl mx-auto">
          <div className="text-center mb-16">
            <h3 className="text-4xl font-bold text-gray-900 mb-4">
              Choose Your Plan
            </h3>
            <p className="text-lg text-gray-600 max-w-3xl mx-auto">
              Flexible pricing options designed to grow with your consulting practice. Start with our free trial and upgrade as your needs evolve.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {pricingPlans.map((plan, index) => (
              <Card key={index} className={`relative ${plan.popular ? 'border-blue-500 shadow-lg' : ''}`}>
                {plan.popular && (
                  <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-1/2">
                    <span className="bg-blue-600 text-white px-4 py-1 rounded-full text-sm font-medium">
                      Most Popular
                    </span>
                  </div>
                )}
                <CardContent className="p-8">
                  <div className="text-center">
                    <h4 className="text-2xl font-bold text-gray-900 mb-2">{plan.name}</h4>
                    <div className="mb-4">
                      <span className="text-4xl font-bold text-gray-900">{plan.price}</span>
                      {plan.price !== 'Custom' && (
                        <span className="text-gray-600 ml-2">{plan.period}</span>
                      )}
                    </div>
                    <p className="text-gray-600 mb-6">{plan.description}</p>
                  </div>
                  
                  <ul className="space-y-3 mb-8">
                    {plan.features.map((feature, featureIndex) => (
                      <li key={featureIndex} className="flex items-center">
                        <span className="text-green-500 mr-3">✓</span>
                        <span className="text-gray-700">{feature}</span>
                      </li>
                    ))}
                  </ul>
                  
                  <Button 
                    className={`w-full ${plan.popular ? '' : 'variant-outline'}`}
                    variant={plan.popular ? 'default' : 'outline'}
                  >
                    {plan.price === 'Custom' ? 'Contact Sales' : 'Start Free Trial'}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-gray-50">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-16">
            <h3 className="text-4xl font-bold text-gray-900 mb-4">
              Frequently Asked Questions
            </h3>
            <p className="text-lg text-gray-600">
              Get answers to common questions about InsightSerenity implementation and features
            </p>
          </div>

          <div className="space-y-6">
            {faqs.map((faq, index) => (
              <Card key={index}>
                <CardContent className="p-6">
                  <h4 className="text-lg font-semibold text-gray-900 mb-3">{faq.question}</h4>
                  <p className="text-gray-700">{faq.answer}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Newsletter Section */}
      <section className="py-16 px-4 sm:px-6 lg:px-8 bg-white">
        <div className="max-w-4xl mx-auto text-center">
          <h3 className="text-3xl font-bold text-gray-900 mb-4">
            Stay Ahead of Industry Trends
          </h3>
          <p className="text-lg text-gray-600 mb-8">
            Subscribe to our newsletter for insights on consulting best practices, industry trends, and platform updates.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center max-w-md mx-auto">
            <input
              type="email"
              placeholder="Enter your email address"
              className="flex-1 px-4 py-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
            <Button className="px-6 py-3">
              Subscribe
            </Button>
          </div>
          <p className="text-sm text-gray-500 mt-4">
            Join 10,000+ consulting professionals. Unsubscribe anytime.
          </p>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4 sm:px-6 lg:px-8 bg-gradient-to-r from-blue-600 to-indigo-600">
        <div className="max-w-4xl mx-auto text-center">
          <h3 className="text-4xl font-bold text-white mb-4">
            Ready to Transform Your Consulting Practice?
          </h3>
          <p className="text-lg text-blue-100 mb-8">
            Join thousands of consultants who are already using InsightSerenity to streamline their operations and deliver exceptional results.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link href="/auth/register">
              <Button variant="secondary" size="lg" className="px-8">
                Start Free Trial
              </Button>
            </Link>
            <Button variant="outline" size="lg" className="px-8 border-white text-white hover:bg-white hover:text-blue-600">
              Schedule Demo
            </Button>
          </div>
          <p className="text-blue-100 mt-4 text-sm">
            No credit card required • 14-day free trial • Cancel anytime
          </p>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-gray-900 text-gray-400 py-16 px-4 sm:px-6 lg:px-8">
        <div className="max-w-7xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-5 gap-8">
            <div className="md:col-span-2">
              <h5 className="text-white font-bold text-xl mb-4 bg-gradient-to-r from-blue-400 to-indigo-400 bg-clip-text text-transparent">
                InsightSerenity
              </h5>
              <p className="text-gray-400 mb-6 max-w-md">
                Empowering consultants with intelligent solutions for modern business challenges. Transform your practice with our comprehensive platform designed for success.
              </p>
              <div className="flex space-x-4">
                <a href="#" className="text-gray-400 hover:text-white transition-colors">
                  <span className="sr-only">LinkedIn</span>
                  <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                  </svg>
                </a>
                <a href="#" className="text-gray-400 hover:text-white transition-colors">
                  <span className="sr-only">Twitter</span>
                  <svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M23.953 4.57a10 10 0 01-2.825.775 4.958 4.958 0 002.163-2.723c-.951.555-2.005.959-3.127 1.184a4.92 4.92 0 00-8.384 4.482C7.69 8.095 4.067 6.13 1.64 3.162a4.822 4.822 0 00-.666 2.475c0 1.71.87 3.213 2.188 4.096a4.904 4.904 0 01-2.228-.616v.06a4.923 4.923 0 003.946 4.827 4.996 4.996 0 01-2.212.085 4.936 4.936 0 004.604 3.417 9.867 9.867 0 01-6.102 2.105c-.39 0-.779-.023-1.17-.067a13.995 13.995 0 007.557 2.209c9.053 0 13.998-7.496 13.998-13.985 0-.21 0-.42-.015-.63A9.935 9.935 0 0024 4.59z"/>
                  </svg>
                </a>
              </div>
            </div>
            
            <div>
              <h6 className="text-white font-semibold mb-4">Product</h6>
              <ul className="space-y-2">
                <li><a href="#" className="hover:text-white transition-colors">Features</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Pricing</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Integrations</a></li>
                <li><a href="#" className="hover:text-white transition-colors">API</a></li>
              </ul>
            </div>
            
            <div>
              <h6 className="text-white font-semibold mb-4">Company</h6>
              <ul className="space-y-2">
                <li><a href="#" className="hover:text-white transition-colors">About</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Careers</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Blog</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Press</a></li>
              </ul>
            </div>
            
            <div>
              <h6 className="text-white font-semibold mb-4">Support</h6>
              <ul className="space-y-2">
                <li><a href="#" className="hover:text-white transition-colors">Help Center</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Contact</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Privacy Policy</a></li>
                <li><a href="#" className="hover:text-white transition-colors">Terms of Service</a></li>
              </ul>
            </div>
          </div>
          
          <div className="border-t border-gray-800 mt-12 pt-8 flex flex-col md:flex-row justify-between items-center">
            <p className="text-sm">
              © 2025 InsightSerenity. All rights reserved.
            </p>
            <p className="text-sm mt-4 md:mt-0">
              Built for consulting excellence. Powered by innovation.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}