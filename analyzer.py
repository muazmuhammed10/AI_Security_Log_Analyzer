import os

from dotenv import load_dotenv
from google import genai


load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

client = genai.Client(api_key=API_KEY)


def generate_analysis(threats, iocs):

    if not threats:
        return {
            "summary": "No major threats were detected.",
            "recommendation": "Continue monitoring the environment."
        }

    prompt = f"""
You are a cybersecurity analyst.

Analyze the following security findings.

Threats:
{threats}

Indicators of Compromise:
{iocs}

Provide:

1. A short security summary.
2. The likely attack type.
3. Why the activity is suspicious.
4. Recommended actions.

Keep the response professional and concise.
Do not invent information that is not present in the findings.
"""

    try:

        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=prompt
        )

        return {
            "summary": response.text,
            "recommendation": (
                "Review the detected threats and investigate "
                "the associated indicators."
            )
        }

    except Exception as e:

        return {
            "summary": "AI analysis is currently unavailable.",
            "recommendation": (
                "Use the rule-based threat detection results "
                "for investigation."
            ),
            "error": str(e)
        }