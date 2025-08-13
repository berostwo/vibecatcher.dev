import Link from "next/link";

export function AppFooter() {
  return (
    <footer className="w-full py-4 mt-16 text-center text-xs text-muted-foreground">
      <div className="flex justify-center gap-4 mb-2">
        <Link href="#" className="hover:text-foreground">Terms of Use</Link>
        <span className="text-muted-foreground">|</span>
        <Link href="#" className="hover:text-foreground">Privacy Policy</Link>
        <span className="text-muted-foreground">|</span>
        <Link href="#" className="hover:text-foreground">Contact</Link>
      </div>
      &copy; {new Date().getFullYear()} VibeCatcher. All rights reserved.
    </footer>
  );
}
