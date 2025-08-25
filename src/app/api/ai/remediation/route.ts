import { NextRequest, NextResponse } from 'next/server';
import OpenAI from 'openai';

// Initialize OpenAI client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

export async function POST(request: NextRequest) {
  try {
    const { prompt, finding } = await request.json();

    if (!prompt) {
      return NextResponse.json(
        { error: 'Prompt is required' },
        { status: 400 }
      );
    }

    // Call ChatGPT API
    const completion = await openai.chat.completions.create({
      model: 'gpt-4',
      messages: [
        {
          role: 'system',
          content: 'You are a senior security engineer helping indie hackers fix security issues. Provide practical, actionable advice with code examples. Be encouraging but direct about security risks.'
        },
        {
          role: 'user',
          content: prompt
        }
      ],
      max_tokens: 1000,
      temperature: 0.3,
    });

    const remediation = completion.choices[0]?.message?.content || 'Unable to generate remediation';

    return NextResponse.json({
      remediation,
      finding_id: finding?.rule_id || 'unknown',
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    console.error('AI remediation generation failed:', error);
    
    // Return a fallback remediation if AI fails
    return NextResponse.json({
      remediation: 'AI remediation generation failed. Please review the security finding manually and consult security best practices for your technology stack.',
      error: 'AI service unavailable',
      timestamp: new Date().toISOString()
    }, { status: 500 });
  }
}
