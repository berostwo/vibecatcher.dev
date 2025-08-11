import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Github } from "lucide-react"

export default function AccountPage() {
  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h1 className="text-6xl font-bold font-headline uppercase italic -mb-6 text-primary/50">Account</h1>
        <p className="text-muted-foreground mt-4">Manage your account details.</p>
      </div>
      <Separator />

      <Card className="border-2 border-primary/20">
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>This is your public profile information.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
           <div className="flex items-center gap-4">
                <Avatar className="h-16 w-16">
                    <AvatarImage src="https://github.com/shadcn.png" alt="@shadcn" />
                    <AvatarFallback>CN</AvatarFallback>
                </Avatar>
                <div>
                    <p className="font-medium text-lg">Your Name</p>
                    <p className="text-sm text-muted-foreground">your.email@example.com</p>
                </div>
           </div>
           <div className="flex items-center gap-2 pt-2">
            <Github className="w-4 h-4 text-muted-foreground"/>
            <span className="text-sm text-muted-foreground">Connected to: your-github-username</span>
           </div>
        </CardContent>
        <CardFooter>
            <Button variant="outline">Edit Profile</Button>
        </CardFooter>
      </Card>
    </div>
  )
}
