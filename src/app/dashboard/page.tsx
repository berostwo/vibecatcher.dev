import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Github, History, ShieldCheck, ArrowRight, CheckCircle, ShoppingCart } from 'lucide-react'
import Link from 'next/link'
import { DashboardPage, DashboardPageHeader } from '@/components/common/dashboard-page'

export default function DashboardPageContent() {
  return (
    <DashboardPage>
      <DashboardPageHeader title="Dashboard" description="An overview of your account and security audits." />
      
      <div className="grid gap-6 md:grid-cols-2">
        <Card className="bg-gradient-to-r from-primary/10 to-accent/10 border-2 border-primary/20">
            <CardHeader>
                <CardTitle>Hello, User!</CardTitle>
                 <CardDescription>
                    Ready to secure your code?
                </CardDescription>
            </CardHeader>
            <CardContent>
                <Button asChild>
                    <Link href="/dashboard/security-audit">
                        Start Audit
                        <ArrowRight className="ml-2 h-4 w-4"/>
                    </Link>
                </Button>
            </CardContent>
        </Card>
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Audits Available</CardTitle>
            <CheckCircle className="h-4 w-4 text-primary" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">8</div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Repos</CardTitle>
            <Github className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">12</div>
            <p className="text-xs text-muted-foreground">
              Connected via your GitHub account
            </p>
          </CardContent>
        </Card>
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Audits Performed</CardTitle>
            <History className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">42</div>
            <p className="text-xs text-muted-foreground">
              Across all connected repositories
            </p>
          </CardContent>
        </Card>
        <Card className="border-2 border-primary/20">
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Critical Issues Found</CardTitle>
            <ShieldCheck className="h-destructive" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">3</div>
            <p className="text-xs text-muted-foreground">
              In the last 30 days
            </p>
          </CardContent>
        </Card>
      </div>
    </DashboardPage>
  )
}
