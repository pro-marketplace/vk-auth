/**
 * VK Auth Extension - User Profile
 *
 * Component to display user data after VK login.
 */
import React from "react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";

// =============================================================================
// TYPES
// =============================================================================

interface User {
  id: number;
  email: string | null;
  name: string | null;
  avatar_url: string | null;
  vk_id: string;
}

interface UserProfileProps {
  /** User data from useVkAuth */
  user: User;
  /** Logout function from useVkAuth */
  onLogout: () => Promise<void>;
  /** Loading state */
  isLoading?: boolean;
  /** CSS class for Card */
  className?: string;
}

// =============================================================================
// COMPONENT
// =============================================================================

export function UserProfile({
  user,
  onLogout,
  isLoading = false,
  className = "",
}: UserProfileProps): React.ReactElement {
  const initials = user.name
    ? user.name
        .split(" ")
        .map((n) => n[0])
        .join("")
        .toUpperCase()
        .slice(0, 2)
    : "VK";

  const handleLogout = async () => {
    await onLogout();
  };

  return (
    <Card className={className}>
      <CardHeader className="text-center">
        <div className="flex justify-center mb-4">
          <Avatar className="h-20 w-20">
            {user.avatar_url && <AvatarImage src={user.avatar_url} alt={user.name || "User"} />}
            <AvatarFallback className="text-2xl bg-[#0077FF] text-white">
              {initials}
            </AvatarFallback>
          </Avatar>
        </div>
        <CardTitle className="text-xl">
          {user.name || "Пользователь VK"}
        </CardTitle>
        {user.email && <CardDescription>{user.email}</CardDescription>}
      </CardHeader>

      <CardContent className="space-y-3">
        <div className="flex justify-between text-sm">
          <span className="text-muted-foreground">VK ID</span>
          <span className="font-mono">{user.vk_id}</span>
        </div>

        {user.email && (
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Email</span>
            <span>{user.email}</span>
          </div>
        )}

        {user.name && (
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Имя</span>
            <span>{user.name}</span>
          </div>
        )}
      </CardContent>

      <CardFooter>
        <Button
          variant="outline"
          className="w-full"
          onClick={handleLogout}
          disabled={isLoading}
        >
          {isLoading ? "Выход..." : "Выйти"}
        </Button>
      </CardFooter>
    </Card>
  );
}

export default UserProfile;
