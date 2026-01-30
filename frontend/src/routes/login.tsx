import { Component } from 'solid-js';
import { LoginForm } from '~/components/auth/login_form';
import { ThemeToggle } from '~/components/ui/theme_toggle';

const Login: Component = () => {
  return (
    <div class="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
      {/* Theme toggle in top-right corner */}
      <div class="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      
      <LoginForm />
    </div>
  );
};

export default Login;