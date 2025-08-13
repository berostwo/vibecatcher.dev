import type { PropsWithChildren } from "react";

export function DashboardPage({ children }: PropsWithChildren) {
    return (
        <div className="space-y-6 animate-fade-in-up">
            {children}
        </div>
    )
}

export function DashboardPageHeader({ title, description }: { title: string, description: string }) {
    return (
        <div>
            <h1 className="text-6xl font-bold font-headline uppercase italic -mb-6 text-primary/50">{title}</h1>
            <p className="text-muted-foreground mt-4">{description}</p>
        </div>
    )
}