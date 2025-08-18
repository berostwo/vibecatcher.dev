import * as React from 'react';

import {cn} from '@/lib/utils';

type SecureTextareaProps = React.ComponentProps<'textarea'> & {
  stripControlChars?: boolean;
  disallowHtmlTags?: boolean;
  trimWhitespace?: boolean;
  maxAllowedLength?: number;
  onInvalidInput?: (reason: 'maxLength' | 'html' | 'controlChars', value: string) => void;
};

const sanitizeValue = (
  value: string,
  options: { stripControlChars?: boolean; disallowHtmlTags?: boolean; trimWhitespace?: boolean; maxAllowedLength?: number },
  onInvalid?: (reason: 'maxLength' | 'html' | 'controlChars', value: string) => void
) => {
  let sanitized = value;
  let invalidReason: 'maxLength' | 'html' | 'controlChars' | null = null;

  if (options.stripControlChars) {
    const cleaned = sanitized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
    if (cleaned !== sanitized) {
      invalidReason = 'controlChars';
      sanitized = cleaned;
    }
  }

  if (options.disallowHtmlTags) {
    // Remove HTML tags (lightweight client-side protection; server should still sanitize)
    const cleaned = sanitized.replace(/<[^>]*>/g, '');
    if (cleaned !== sanitized) {
      invalidReason = invalidReason || 'html';
      sanitized = cleaned;
    }
  }

  if (options.trimWhitespace) {
    sanitized = sanitized.trim();
  }

  if (typeof options.maxAllowedLength === 'number' && options.maxAllowedLength > 0 && sanitized.length > options.maxAllowedLength) {
    invalidReason = 'maxLength';
    sanitized = sanitized.slice(0, options.maxAllowedLength);
  }

  if (invalidReason && onInvalid) {
    onInvalid(invalidReason, value);
  }

  return sanitized;
};

const Textarea = React.forwardRef<HTMLTextAreaElement, SecureTextareaProps>(
  ({className, onChange, stripControlChars = false, disallowHtmlTags = false, trimWhitespace = false, maxAllowedLength, onInvalidInput, ...props}, ref) => {
    const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      const el = e.currentTarget;
      const original = el.value;
      const sanitized = sanitizeValue(original, { stripControlChars, disallowHtmlTags, trimWhitespace, maxAllowedLength }, onInvalidInput);

      if (sanitized !== original) {
        const start = el.selectionStart ?? sanitized.length;
        const end = el.selectionEnd ?? sanitized.length;
        el.value = sanitized;
        try {
          // Preserve cursor position where possible
          el.setSelectionRange(start, end);
        } catch {}
      }

      onChange?.(e);
    };

    return (
      <textarea
        className={cn(
          'flex min-h-[80px] w-full rounded-md border border-input bg-background px-3 py-2 text-base ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 md:text-sm',
          className
        )}
        ref={ref}
        onChange={handleChange}
        {...props}
      />
    );
  }
);
Textarea.displayName = 'Textarea';

export {Textarea};
