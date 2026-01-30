import { Component } from 'solid-js';
import { A } from '@solidjs/router';
import { Button } from '~/components/ui/button';
import { themeClasses, cn } from '~/utils/theme';

const NotFound: Component = () => {
  return (
    <div class="flex flex-col items-center justify-center min-h-[60vh] text-center">
      <h1 class={cn("text-9xl font-bold", themeClasses.textMuted)}>404</h1>
      <h2 class={cn("text-2xl font-semibold mt-4", themeClasses.textPrimary)}>Page Not Found</h2>
      <p class={cn("mt-2 mb-8", themeClasses.textSecondary)}>
        The page you're looking for doesn't exist.
      </p>
      <A href="/dashboard">
        <Button variant="primary">Go to Dashboard</Button>
      </A>
    </div>
  );
};

export default NotFound;