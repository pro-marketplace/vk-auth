/**
 * VK Auth Extension - VK Login Button
 *
 * Ready-to-use VK login button component.
 */
import React from "react";
import { Button } from "@/components/ui/button";

// =============================================================================
// TYPES
// =============================================================================

interface VkLoginButtonProps {
  /** Click handler - call auth.login() from useVkAuth */
  onClick: () => void;
  /** Loading state */
  isLoading?: boolean;
  /** Button text */
  buttonText?: string;
  /** CSS class */
  className?: string;
  /** Disabled state */
  disabled?: boolean;
}

// =============================================================================
// SPINNER
// =============================================================================

function Spinner({ className }: { className?: string }) {
  return (
    <svg
      className={`animate-spin ${className}`}
      xmlns="http://www.w3.org/2000/svg"
      fill="none"
      viewBox="0 0 24 24"
    >
      <circle
        className="opacity-25"
        cx="12"
        cy="12"
        r="10"
        stroke="currentColor"
        strokeWidth="4"
      />
      <path
        className="opacity-75"
        fill="currentColor"
        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
      />
    </svg>
  );
}

// =============================================================================
// VK ICON
// =============================================================================

function VkIcon({ className }: { className?: string }) {
  return (
    <svg
      className={className}
      viewBox="0 0 24 24"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
    >
      <path d="M12.785 16.241s.288-.032.436-.194c.136-.148.132-.427.132-.427s-.02-1.304.587-1.496c.596-.19 1.365 1.26 2.179 1.818.615.42 1.083.328 1.083.328l2.175-.03s1.138-.07.598-.964c-.044-.073-.314-.661-1.618-1.869-1.366-1.266-1.183-1.061.462-3.252.999-1.333 1.398-2.146 1.273-2.494-.12-.332-.854-.244-.854-.244l-2.449.015s-.182-.025-.316.056c-.131.079-.216.264-.216.264s-.386 1.028-.901 1.902c-1.088 1.848-1.523 1.946-1.7 1.832-.413-.267-.31-1.075-.31-1.649 0-1.794.272-2.541-.529-2.735-.266-.064-.462-.107-1.142-.114-.873-.009-1.612.003-2.03.208-.279.137-.494.442-.363.459.162.021.529.099.723.364.251.342.242 1.11.242 1.11s.144 2.111-.336 2.372c-.33.18-.783-.187-1.755-1.866-.498-.859-.874-1.81-.874-1.81s-.072-.177-.201-.272c-.156-.115-.375-.151-.375-.151l-2.327.015s-.349.01-.477.161c-.114.135-.009.413-.009.413s1.816 4.25 3.87 6.392c1.883 1.965 4.022 1.836 4.022 1.836h.97z" />
    </svg>
  );
}

// =============================================================================
// COMPONENT
// =============================================================================

export function VkLoginButton({
  onClick,
  isLoading = false,
  buttonText = "Войти через ВК",
  className = "",
  disabled = false,
}: VkLoginButtonProps): React.ReactElement {
  return (
    <Button
      onClick={onClick}
      disabled={disabled || isLoading}
      className={`bg-[#0077FF] hover:bg-[#0066DD] text-white ${className}`}
    >
      {isLoading ? (
        <Spinner className="!w-5 !h-5 mr-2 flex-shrink-0" />
      ) : (
        <VkIcon className="!w-6 !h-7 mr-1 flex-shrink-0 justify-start" />
      )}
      {isLoading ? "Загрузка..." : buttonText}
    </Button>
  );
}

export default VkLoginButton;
