"use client"

import * as React from "react"
import * as ProgressPrimitive from "@radix-ui/react-progress"

import { cn } from "@/lib/utils"

type ProgressProps = React.ComponentPropsWithoutRef<typeof ProgressPrimitive.Root> & {
	value?: number | string | null | undefined
}

const sanitizeProgress = (raw: ProgressProps["value"]): number => {
	let n: number = 0
	if (typeof raw === "number") n = raw
	else if (typeof raw === "string") n = Number(raw)
	else n = 0
	if (!Number.isFinite(n)) n = 0
	if (n < 0) n = 0
	if (n > 100) n = 100
	return Math.round(n)
}

const Progress = React.forwardRef<
	React.ElementRef<typeof ProgressPrimitive.Root>,
	ProgressProps
>(({ className, value, ...props }, ref) => {
	const safeValue = sanitizeProgress(value)
	return (
		<ProgressPrimitive.Root
			ref={ref}
			className={cn(
				"relative h-4 w-full overflow-hidden rounded-full bg-secondary",
				className
			)}
			{...props}
		>
			<ProgressPrimitive.Indicator
				className="h-full w-full flex-1 bg-primary transition-all"
				style={{ transform: `translateX(-${100 - safeValue}%)` }}
			/>
		</ProgressPrimitive.Root>
	)
})
Progress.displayName = ProgressPrimitive.Root.displayName

export { Progress }
