// src/components/auth/RegisterForm.tsx
'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { apiClient } from '@/lib/api';
import { AuthService } from '@/lib/auth';
import { validateEmail, validatePassword } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';
import { Alert } from '@/components/ui/Alert';

export function RegisterForm() {
  const router = useRouter();
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: '',
    acceptTerms: false,
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isLoading, setIsLoading] = useState(false);
  const [alertMessage, setAlertMessage] = useState<{ type: 'error' | 'success'; message: string } | null>(null);

  const validateForm = () => {
    const newErrors: Record<string, string> = {};

    if (!formData.firstName.trim()) {
      newErrors.firstName = 'First name is required';
    }

    if (!formData.lastName.trim()) {
      newErrors.lastName = 'Last name is required';
    }

    if (!formData.email) {
      newErrors.email = 'Email is required';
    } else if (!validateEmail(formData.email)) {
      newErrors.email = 'Invalid email format';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else {
      const passwordValidation = validatePassword(formData.password);
      if (!passwordValidation.isValid) {
        newErrors.password = passwordValidation.errors[0];
      }
    }

    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Passwords do not match';
    }

    if (!formData.acceptTerms) {
      newErrors.acceptTerms = 'You must accept the terms and conditions';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAlertMessage(null);

    if (!validateForm()) return;

    setIsLoading(true);
    try {
      const response = await apiClient.register({
        email: formData.email,
        password: formData.password,
        firstName: formData.firstName,
        lastName: formData.lastName,
        acceptTerms: formData.acceptTerms,
      });

      if (response.success && response.data) {
        AuthService.saveTokens(response.data.tokens);
        AuthService.saveUser(response.data.user);
        
        setAlertMessage({
          type: 'success',
          message: 'Account created successfully! Redirecting to dashboard...',
        });

        setTimeout(() => {
          router.push('/dashboard');
        }, 2000);
      }
    } catch (error: any) {
      setAlertMessage({
        type: 'error',
        message: error.message || 'Registration failed. Please try again.',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
    // Clear error for this field
    if (errors[name]) {
      setErrors(prev => ({ ...prev, [name]: '' }));
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {alertMessage && (
        <Alert 
          variant={alertMessage.type} 
          onClose={() => setAlertMessage(null)}
        >
          {alertMessage.message}
        </Alert>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Input
          label="First Name"
          type="text"
          name="firstName"
          value={formData.firstName}
          onChange={handleInputChange}
          error={errors.firstName}
          placeholder="John"
          autoComplete="given-name"
          required
        />

        <Input
          label="Last Name"
          type="text"
          name="lastName"
          value={formData.lastName}
          onChange={handleInputChange}
          error={errors.lastName}
          placeholder="Doe"
          autoComplete="family-name"
          required
        />
      </div>

      <Input
        label="Email Address"
        type="email"
        name="email"
        value={formData.email}
        onChange={handleInputChange}
        error={errors.email}
        placeholder="john.doe@company.com"
        autoComplete="email"
        required
      />

      <Input
        label="Password"
        type="password"
        name="password"
        value={formData.password}
        onChange={handleInputChange}
        error={errors.password}
        placeholder="••••••••"
        helperText="Must be at least 12 characters with uppercase, lowercase, number and special character"
        autoComplete="new-password"
        required
      />

      <Input
        label="Confirm Password"
        type="password"
        name="confirmPassword"
        value={formData.confirmPassword}
        onChange={handleInputChange}
        error={errors.confirmPassword}
        placeholder="••••••••"
        autoComplete="new-password"
        required
      />

      <div className="space-y-2">
        <label className="flex items-start">
          <input
            type="checkbox"
            name="acceptTerms"
            checked={formData.acceptTerms}
            onChange={handleInputChange}
            className="mt-0.5 h-3.5 w-3.5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          />
          <span className="ml-2 text-xs text-gray-600">
            I agree to the{' '}
            <Link href="/terms" className="text-blue-600 hover:text-blue-500">
              Terms and Conditions
            </Link>{' '}
            and{' '}
            <Link href="/privacy" className="text-blue-600 hover:text-blue-500">
              Privacy Policy
            </Link>
          </span>
        </label>
        {errors.acceptTerms && (
          <p className="text-xs text-red-600 ml-5">{errors.acceptTerms}</p>
        )}
      </div>

      <Button
        type="submit"
        className="w-full"
        isLoading={isLoading}
        disabled={isLoading}
      >
        Create Account
      </Button>

      <p className="text-center text-xs text-gray-600">
        Already have an account?{' '}
        <Link href="/login" className="font-medium text-blue-600 hover:text-blue-500">
          Sign in
        </Link>
      </p>
    </form>
  );
}