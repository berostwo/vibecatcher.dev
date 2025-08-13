import { Badge, type BadgeProps } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Clock, SquareMenu, ShieldAlert, AlertTriangle, Info, Code, CheckCircle } from "lucide-react"
import { DashboardPage, DashboardPageHeader } from "@/components/common/dashboard-page"

const auditHistory = [
  {
    id: "AUD-001",
    repo: "my-awesome-app",
    date: "2024-05-20",
    status: "Completed",
    summary: { totalIssues: 3, critical: 1, high: 1, medium: 1, low: 0 },
    vulnerabilities: [
      { id: "VULN-002", title: "Cross-Site Scripting (XSS)", severity: "Critical", file: "src/components/Comment.tsx", line: 42, description: "User-provided content is rendered without proper sanitization, allowing for potential XSS attacks.", remediation: "Use a library like `dompurify` to sanitize HTML content before rendering it with `dangerouslySetInnerHTML`." },
      { id: "VULN-001", title: "Outdated Dependency: `react-scripts`", severity: "High", file: "package.json", line: 25, description: "The version of `react-scripts` used in this project is outdated and has known security vulnerabilities.", remediation: "Update `react-scripts` to the latest version by running `npm install react-scripts@latest`." },
      { id: "VULN-003", title: "Insecure `target='_blank'` usage", severity: "Medium", file: "src/components/Footer.tsx", line: 15, description: "Links using `target='_blank'` without `rel='noopener noreferrer'` are a security risk.", remediation: "Add `rel='noopener noreferrer'` to all `<a>` tags that have `target='_blank'`." },
    ],
  },
  {
    id: "AUD-002",
    repo: "legacy-backend",
    date: "2024-05-18",
    status: "Completed",
    summary: { totalIssues: 2, critical: 1, high: 0, medium: 1, low: 0 },
    vulnerabilities: [
      { id: "VULN-004", title: "SQL Injection", severity: "Critical", file: "server/db/queries.js", line: 112, description: "Database queries are constructed with raw user input, making them vulnerable to SQL injection.", remediation: "Use parameterized queries or an ORM to interact with the database safely." },
      { id: "VULN-005", title: "Missing CSRF Protection", severity: "Medium", file: "server/app.js", line: 56, description: "No CSRF tokens are used, leaving state-changing endpoints vulnerable to Cross-Site Request Forgery.", remediation: "Implement CSRF token validation for all non-GET requests. Libraries like `csurf` can help." },
    ]
  },
  {
    id: "AUD-003",
    repo: "new-frontend-library",
    date: "2024-05-15",
    status: "Completed",
    summary: { totalIssues: 8, critical: 2, high: 3, medium: 3, low: 0 },
    vulnerabilities: [
        // For brevity, vulnerabilities are illustrative
    ],
  },
  {
    id: "AUD-004",
    repo: "secure-app-example",
    date: "2024-04-29",
    status: "Completed",
    summary: { totalIssues: 0, critical: 0, high: 0, medium: 0, low: 0 },
    vulnerabilities: [],
  },
]


const getSeverityStyles = (severity: string) => {
  switch (severity) {
    case 'Critical':
      return {
        icon: <ShieldAlert className="h-5 w-5 text-red-500" />,
        borderColor: 'border-red-500/50',
        bgColor: 'bg-red-500/10',
        textColor: 'text-red-500',
      };
    case 'High':
      return {
        icon: <AlertTriangle className="h-5 w-5 text-orange-500" />,
        borderColor: 'border-orange-500/50',
        bgColor: 'bg-orange-500/10',
        textColor: 'text-orange-500',
      };
    case 'Medium':
      return {
        icon: <Info className="h-5 w-5 text-yellow-500" />,
        borderColor: 'border-yellow-500/50',
        bgColor: 'bg-yellow-500/10',
        textColor: 'text-yellow-500',
      };
    default:
      return {
        icon: <CheckCircle className="h-5 w-5 text-green-500" />,
        borderColor: 'border-gray-500/50',
        bgColor: 'bg-green-500/10',
        textColor: 'text-green-500',
      };
  }
};


export default function AuditHistoryPage() {
  const getBadgeVariant = (issues: number): BadgeProps["variant"] => {
    if (issues > 5) return "destructive"
    if (issues > 0) return "secondary"
    return "default"
  }

  const getHealthColor = (score: number) => {
    if (score > 85) return 'text-green-500';
    if (score > 60) return 'text-yellow-500';
    if (score > 40) return 'text-orange-500';
    return 'text-red-500';
  }

  const calculateHealthScore = (summary: typeof auditHistory[0]['summary']) => {
    if (!summary.totalIssues) return 100;
    const weightedScore = (summary.critical * 10) + (summary.high * 5) + (summary.medium * 2) + (summary.low * 1);
    const maxScore = summary.totalIssues * 10;
    return Math.max(0, Math.round((1 - (weightedScore / (maxScore || 1))) * 100));
  }


  return (
    <DashboardPage>
      <DashboardPageHeader title="Audit History" description="Review and track the history of your previous audits." />
      <Accordion type="single" collapsible className="w-full space-y-4">
        {auditHistory.map((audit) => {
          const healthScore = calculateHealthScore(audit.summary);
          return (
          <AccordionItem
            value={audit.id}
            key={audit.id}
            className="rounded-lg border-2 border-primary/20 bg-card/50 shadow-sm px-4"
          >
            <AccordionTrigger className="hover:no-underline">
              <div className="flex justify-between items-center w-full">
                <div className="flex items-center gap-4">
                    <SquareMenu className="h-4 w-4 text-primary" />
                    <span className="font-medium">{audit.repo}</span>
                </div>
                <div className="flex items-center gap-6">
                    <div className="hidden sm:flex items-center gap-2 text-muted-foreground">
                        <Clock className="h-4 w-4" />
                        <span>{audit.date}</span>
                    </div>
                </div>
              </div>
            </AccordionTrigger>
            <AccordionContent className="pt-2 pb-4">
              {audit.summary.totalIssues > 0 ? (
                <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4 text-center">
                        <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-muted-foreground">Total Findings</h4>
                            <p className="text-4xl font-bold">{audit.summary.totalIssues}</p>
                        </div>
                        <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
                            <h4 className="text-sm font-medium text-muted-foreground">Codebase Health</h4>
                            <p className={`text-4xl font-bold ${getHealthColor(healthScore)}`}>{healthScore}%</p>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
                      <div className="border border-red-500/50 bg-red-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-red-400">Critical</h4>
                        <p className="text-2xl font-bold text-red-500">{audit.summary.critical}</p>
                      </div>
                      <div className="border border-orange-500/50 bg-orange-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-orange-400">High</h4>
                        <p className="text-2xl font-bold text-orange-500">{audit.summary.high}</p>
                      </div>
                      <div className="border border-yellow-500/50 bg-yellow-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-yellow-400">Medium</h4>
                        <p className="text-2xl font-bold text-yellow-500">{audit.summary.medium}</p>
                      </div>
                      <div className="border border-green-500/50 bg-green-500/10 rounded-lg p-2">
                        <h4 className="text-sm font-medium text-green-400">Low</h4>
                        <p className="text-2xl font-bold text-green-500">{audit.summary.low}</p>
                      </div>
                    </div>
                    <Accordion type="single" collapsible className="w-full">
                        {audit.vulnerabilities.map((vuln) => {
                            const { icon, borderColor, bgColor, textColor } = getSeverityStyles(vuln.severity);
                            return (
                            <AccordionItem value={vuln.id} key={vuln.id} className={`rounded-lg mb-4 border ${borderColor} ${bgColor} px-4 shadow-sm`}>
                                <AccordionTrigger className="hover:no-underline">
                                    <div className="flex items-center gap-4 w-full">
                                        {icon}
                                        <div className="flex-grow text-left">
                                            <p className={`font-semibold ${textColor}`}>{vuln.title}</p>
                                            <p className="text-sm text-muted-foreground font-mono">{vuln.file}:{vuln.line}</p>
                                        </div>
                                    </div>
                                </AccordionTrigger>
                                <AccordionContent className="pt-2">
                                    <p className="text-sm text-foreground/80 mb-4">{vuln.description}</p>
                                    <div className="bg-card/50 p-4 rounded-md border border-border">
                                        <h4 className="font-semibold mb-2 flex items-center"><Code className="mr-2 h-4 w-4" /> Remediation</h4>
                                        <div className="bg-black/80 rounded-md p-3">
                                            <pre className="text-xs text-green-300 whitespace-pre-wrap font-code">
                                                {vuln.remediation}
                                            </pre>
                                        </div>
                                    </div>
                                </AccordionContent>
                            </AccordionItem>
                            );
                        })}
                    </Accordion>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center text-center text-muted-foreground p-8">
                    <CheckCircle className="w-12 h-12 text-green-500 mb-4" />
                    <h3 className="text-lg font-semibold text-foreground">No Issues Found</h3>
                    <p>Excellent! This repository passed the security audit.</p>
                </div>
              )}
            </AccordionContent>
          </AccordionItem>
        )})}
      </Accordion>
    </DashboardPage>
  )
}
