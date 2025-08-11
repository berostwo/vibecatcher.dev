"use client"

import { useState, useMemo } from "react"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion"
import { Badge } from "@/components/ui/badge"
import { ArrowRight, Loader2, CheckCircle, ShieldAlert, AlertTriangle, Info, Terminal, Code } from "lucide-react"

// Mock data
const mockRepos = [
  { id: "1", name: "my-awesome-app" },
  { id: "2", name: "legacy-backend" },
  { id: "3", name: "new-frontend-library" },
  { id: "4", name: "secure-app-example" },
]

const mockAuditResultsData = {
  "my-awesome-app": {
    repoName: "my-awesome-app",
    summary: { totalIssues: 3, critical: 1, high: 1, medium: 1, low: 0 },
    vulnerabilities: [
      { id: "VULN-002", title: "Cross-Site Scripting (XSS)", severity: "Critical", file: "src/components/Comment.tsx", line: 42, description: "User-provided content is rendered without proper sanitization, allowing for potential XSS attacks.", remediation: "Use a library like `dompurify` to sanitize HTML content before rendering it with `dangerouslySetInnerHTML`." },
      { id: "VULN-001", title: "Outdated Dependency: `react-scripts`", severity: "High", file: "package.json", line: 25, description: "The version of `react-scripts` used in this project is outdated and has known security vulnerabilities.", remediation: "Update `react-scripts` to the latest version by running `npm install react-scripts@latest`." },
      { id: "VULN-003", title: "Insecure `target='_blank'` usage", severity: "Medium", file: "src/components/Footer.tsx", line: 15, description: "Links using `target='_blank'` without `rel='noopener noreferrer'` are a security risk.", remediation: "Add `rel='noopener noreferrer'` to all `<a>` tags that have `target='_blank'`." },
    ],
  },
  "legacy-backend": {
    repoName: "legacy-backend",
    summary: { totalIssues: 2, critical: 1, high: 0, medium: 1, low: 0 },
    vulnerabilities: [
      { id: "VULN-004", title: "SQL Injection", severity: "Critical", file: "server/db/queries.js", line: 112, description: "Database queries are constructed with raw user input, making them vulnerable to SQL injection.", remediation: "Use parameterized queries or an ORM to interact with the database safely." },
      { id: "VULN-005", title: "Missing CSRF Protection", severity: "Medium", file: "server/app.js", line: 56, description: "No CSRF tokens are used, leaving state-changing endpoints vulnerable to Cross-Site Request Forgery.", remediation: "Implement CSRF token validation for all non-GET requests. Libraries like `csurf` can help." },
    ]
  },
  "secure-app-example": {
    repoName: "secure-app-example",
    summary: { totalIssues: 0, critical: 0, high: 0, medium: 0, low: 0 },
    vulnerabilities: [],
  },
}

const getSeverityStyles = (severity: string) => {
  switch (severity) {
    case 'Critical':
      return {
        icon: <ShieldAlert className="h-5 w-5 text-red-500" />,
        badgeVariant: 'destructive' as const,
        borderColor: 'border-red-500/50',
        bgColor: 'bg-red-500/10',
        textColor: 'text-red-500',
      };
    case 'High':
      return {
        icon: <AlertTriangle className="h-5 w-5 text-orange-500" />,
        badgeVariant: 'destructive' as const,
        borderColor: 'border-orange-500/50',
        bgColor: 'bg-orange-500/10',
        textColor: 'text-orange-500',
      };
    case 'Medium':
      return {
        icon: <Info className="h-5 w-5 text-yellow-500" />,
        badgeVariant: 'secondary' as const,
        borderColor: 'border-yellow-500/50',
        bgColor: 'bg-yellow-500/10',
        textColor: 'text-yellow-500',
      };
    default:
      return {
        icon: <CheckCircle className="h-5 w-5 text-green-500" />,
        badgeVariant: 'outline' as const,
        borderColor: 'border-gray-500/50',
        bgColor: 'bg-green-500/10',
        textColor: 'text-green-500',
      };
  }
};


type AuditResultsType = typeof mockAuditResultsData[keyof typeof mockAuditResultsData] | null;

const AuditReport = ({ results }: { results: NonNullable<AuditResultsType> }) => {
    const healthScore = useMemo(() => {
        if (!results.summary.totalIssues) return 100;
        const weightedScore = (results.summary.critical * 10) + (results.summary.high * 5) + (results.summary.medium * 2) + (results.summary.low * 1);
        const maxScore = results.summary.totalIssues * 10;
        return Math.max(0, Math.round((1 - (weightedScore / maxScore)) * 100));
    }, [results]);
    
  const getHealthColor = (score: number) => {
    if (score > 85) return 'text-green-500';
    if (score > 60) return 'text-yellow-500';
    if (score > 40) return 'text-orange-500';
    return 'text-red-500';
  }

  const severityOrder = useMemo(() => ['Critical', 'High', 'Medium', 'Low'], []);
  const sortedVulnerabilities = useMemo(() => {
    return results.vulnerabilities.sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)) || [];
  }, [results, severityOrder]);

  return (
    <Card className="bg-card/50 border-2 border-primary/20 shadow-2xl shadow-primary/10">
      <CardHeader>
        <div className="flex flex-col md:flex-row justify-between items-start mb-6">
          <div className="mb-4 md:mb-0">
            <CardTitle className="text-2xl">Audit Report: `{results.repoName}`</CardTitle>
            <CardDescription>{results.summary.totalIssues} vulnerabilities found. See details below.</CardDescription>
          </div>
        </div>
        <div className="space-y-4 text-center">
          <div className="grid grid-cols-2 gap-4">
            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
              <h4 className="text-sm font-medium text-muted-foreground">Total Findings</h4>
              <p className="text-4xl font-bold">{results.summary.totalIssues}</p>
            </div>
            <div className="border border-foreground/20 bg-foreground/5 rounded-lg p-4">
              <h4 className="text-sm font-medium text-muted-foreground">Codebase Health</h4>
              <p className={`text-4xl font-bold ${getHealthColor(healthScore)}`}>{healthScore}%</p>
            </div>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="border border-red-500/50 bg-red-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-red-400">Critical</h4>
              <p className="text-4xl font-bold text-red-500">{results.summary.critical}</p>
            </div>
            <div className="border border-orange-500/50 bg-orange-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-orange-400">High</h4>
              <p className="text-4xl font-bold text-orange-500">{results.summary.high}</p>
            </div>
            <div className="border border-yellow-500/50 bg-yellow-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-yellow-400">Medium</h4>
              <p className="text-4xl font-bold text-yellow-500">{results.summary.medium}</p>
            </div>
            <div className="border border-green-500/50 bg-green-500/10 rounded-lg p-4">
              <h4 className="text-sm font-medium text-green-400">Low</h4>
              <p className="text-4xl font-bold text-green-500">{results.summary.low}</p>
            </div>
          </div>
          <Accordion type="single" collapsible className="w-full">
            <AccordionItem value="master-prompt" className="border border-foreground/20 bg-foreground/5 rounded-lg shadow-sm">
              <AccordionTrigger className="hover:no-underline px-4 py-3">
                <div className="flex items-center gap-2 text-foreground">
                  <Terminal className="mr-2 h-4 w-4" /> View Master Prompt
                </div>
              </AccordionTrigger>
              <AccordionContent className="px-4 pb-4">
                <div className="bg-black/80 rounded-md p-3 text-left">
                  <pre className="text-xs text-green-300 whitespace-pre-wrap font-code text-left">
                    {`You are an expert security engineer. Given the following list of vulnerabilities, provide the necessary code changes to remediate all of them. For each vulnerability, explain the risk and the fix.

${sortedVulnerabilities.map((v, i) => `Vulnerability ${i + 1}: ${v.title} in '${v.file}' on line ${v.line}.\nDescription: ${v.description}...`).join('\n\n')}

Provide a git-compatible diff for each required code change.`}
                  </pre>
                </div>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </div>
      </CardHeader>
      <CardContent>
        <Accordion type="single" collapsible className="w-full">
          {sortedVulnerabilities.map((vuln) => {
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
                    <h4 className="font-semibold mb-2 flex items-center"><Code className="mr-2 h-4 w-4" /> Remediation Prompt</h4>
                    <div className="bg-black/80 rounded-md p-3">
                      <pre className="text-xs text-green-300 whitespace-pre-wrap font-code">
                        {`Explain the security vulnerability "${vuln.title}" found in the file \`${vuln.file}\` and provide the corrected code snippet to fix it. The vulnerability is described as: "${vuln.description}". The recommended fix is: "${vuln.remediation}"`}
                      </pre>
                    </div>
                  </div>
                </AccordionContent>
              </AccordionItem>
            );
          })}
        </Accordion>
      </CardContent>
    </Card>
  )
}

export default function SecurityAuditPage() {
  const [selectedRepo, setSelectedRepo] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [auditResults, setAuditResults] = useState<AuditResultsType>(null)

  const handleAudit = () => {
    if (!selectedRepo) return
    setIsLoading(true)
    setAuditResults(null)
    setTimeout(() => {
      const results = mockAuditResultsData[selectedRepo as keyof typeof mockAuditResultsData] || { repoName: selectedRepo, summary: { totalIssues: 0, critical: 0, high: 0, medium: 0, low: 0 }, vulnerabilities: [] };
      setAuditResults(results)
      setIsLoading(false)
    }, 2000)
  }

  return (
    <div className="space-y-6 animate-fade-in-up">
      <div>
        <h1 className="text-6xl font-bold font-headline uppercase italic -mb-6 text-primary/50">Security Audit</h1>
        <p className="text-muted-foreground mt-4">
          Select a GitHub repository to start your security audit.
        </p>
      </div>

      <Card className="border-2 border-primary/20">
        <CardHeader>
          <CardTitle>Select Repository</CardTitle>
          <CardDescription>
            Choose a repository from the list to begin the audit process.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Select onValueChange={setSelectedRepo} disabled={isLoading}>
            <SelectTrigger className="w-full md:w-[300px]">
              <SelectValue placeholder="Select a repository" />
            </SelectTrigger>
            <SelectContent>
              {mockRepos.map((repo) => (
                <SelectItem key={repo.id} value={repo.name}>
                  {repo.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </CardContent>
        <CardFooter>
          <Button onClick={handleAudit} disabled={!selectedRepo || isLoading}>
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Auditing...
              </>
            ) : (
              <>
                Start Audit <ArrowRight className="ml-2 h-4 w-4" />
              </>
            )}
          </Button>
        </CardFooter>
      </Card>

      {auditResults && auditResults.summary.totalIssues > 0 && (
        <AuditReport results={auditResults} />
      )}

      {auditResults && auditResults.summary.totalIssues === 0 && (
         <Card className="border-green-500/30">
            <CardHeader className="flex-row items-center gap-4">
                <CheckCircle className="w-8 h-8 text-green-500" />
                <div>
                    <CardTitle>No Issues Found!</CardTitle>
                    <CardDescription>
                        Excellent! Your repository `{auditResults.repoName}` passed the security audit.
                    </CardDescription>
                </div>
            </CardHeader>
        </Card>
      )}

    </div>
  )
}
