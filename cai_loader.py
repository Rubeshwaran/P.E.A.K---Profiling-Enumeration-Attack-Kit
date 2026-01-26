import sys
import os
import warnings
import logging
import asyncio
import inspect
import json
import datetime

# 1. Suppress Warnings & Configuration Errors
warnings.filterwarnings("ignore")
logging.getLogger().setLevel(logging.ERROR)

# 2. WINDOWS COMPATIBILITY PATCH
class MockUnix:
    """Fake Linux modules to prevent Windows crashes."""
    TCSADRAIN, TCSANOW, TCOON, TCOOFF, ECHO, ICANON = 0, 0, 0, 0, 1, 2
    def __getattr__(self, name): return 0 if name.isupper() else self._dummy
    def _dummy(self, *args, **kwargs): return [0, 0, 0, 0, 0, 0, []]
    def setraw(self, *args, **kwargs): pass
    def tcgetattr(self, *args, **kwargs): return [0, 0, 0, 0, 0, 0, []]

sys.modules['termios'] = MockUnix()
sys.modules['tty'] = MockUnix()
sys.modules['pty'] = MockUnix()
sys.modules['fcntl'] = MockUnix()
sys.modules['resource'] = MockUnix()

# 3. MANUAL EXECUTION FALLBACK (The Engine)
async def manual_execution_fallback(agent, prompt):
    """
    If the agent object has no .run() method (Swarm/MCP style),
    we manually run it using the configured API keys.
    """
    try:
        from openai import AsyncOpenAI
    except ImportError:
        return "ERROR: 'openai' library missing. Install it with: pip install openai"

    # --- 1. Extract System Prompt / Instructions ---
    system_prompt = "You are a helpful assistant."
    if hasattr(agent, "get_system_prompt"):
        try:
            system_prompt = agent.get_system_prompt()
        except:
            pass
    elif hasattr(agent, "instructions"):
        inst = agent.instructions
        system_prompt = inst() if callable(inst) else str(inst)

    # --- 2. Extract & Sanitize Model Name ---
    raw_model = getattr(agent, "model", None)
    model_name = "gemini-2.5-flash" # Default fallback

    # Try to extract a string name from the object
    if isinstance(raw_model, str):
        model_name = raw_model
    elif hasattr(raw_model, "id"): 
        model_name = raw_model.id
    elif hasattr(raw_model, "name"):
        model_name = raw_model.name
    
    # If the extracted name is still an object or contains 'gpt', force Gemini
    if not isinstance(model_name, str) or "gpt" in str(model_name).lower():
        model_name = "gemini-1.5-flash"

    # --- 3. Initialize Client (Pointing to Google Gemini) ---
    try:
        client = AsyncOpenAI(
            api_key=os.environ.get("OPENAI_API_KEY"),
            base_url=os.environ.get("OPENAI_API_BASE")
        )

        response = await client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"MANUAL EXECUTION FAILED: {str(e)}"

# 4. MAIN TASK RUNNER
async def run_agent_task(agent_key, prompt):
    try:
        from dotenv import load_dotenv
        load_dotenv() 

        # --- GEMINI AUTO-PATCH ---
        if os.getenv("GOOGLE_API_KEY"):
            if not os.getenv("OPENAI_API_KEY"):
                os.environ["OPENAI_API_KEY"] = os.getenv("GOOGLE_API_KEY")
            
            # Point OpenAI Base URL to Google's Endpoint
            if not os.getenv("OPENAI_API_BASE"):
                os.environ["OPENAI_API_BASE"] = "https://generativelanguage.googleapis.com/v1beta/openai/"

        from cai.agents import get_agent_by_name
        
        try:
            agent = get_agent_by_name(agent_key)
        except:
            agent = get_agent_by_name(f"{agent_key}_agent")

        if not agent:
            print(f"ERROR: Agent '{agent_key}' not found.")
            return

        # --- EXECUTION ROUTING ---
        response_content = ""

        if hasattr(agent, "invoke"):
            try:
                result = await agent.invoke({"input": prompt})
            except:
                result = await agent.invoke(prompt)
            
            if hasattr(result, 'content'): response_content = result.content
            elif isinstance(result, dict) and 'output' in result: response_content = result['output']
            else: response_content = str(result)

        elif hasattr(agent, "kickoff"):
            result = await agent.kickoff(inputs={'topic': prompt})
            response_content = str(result)

        elif hasattr(agent, "chat"):
            result = await agent.chat(prompt)
            response_content = str(result)
        
        elif hasattr(agent, "run"):
            result = await agent.run(prompt)
            response_content = str(result)

        else:
            # --- FALLBACK: SWARM / MCP / DATACLASS ---
            response_content = await manual_execution_fallback(agent, prompt)


        # --- STEP 1: SESSION LOGGING (The Memory) ---
        # Save this result so the Report Button can find it later.
        session_file = "current_session_data.json"
        
        # Create entry
        new_entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "agent": agent_key,
            "command": prompt,
            "output": str(response_content) # Ensure string format
        }
        
        # Load existing data or start new list
        session_data = []
        if os.path.exists(session_file):
            try:
                with open(session_file, "r") as f:
                    content = f.read()
                    if content.strip():
                        session_data = json.loads(content)
            except Exception as e:
                # If corrupt, start fresh but maybe log error to stderr?
                # For now, just reset to avoid crash
                session_data = [] 
        
        # Append and Save
        session_data.append(new_entry)
        
        try:
            with open(session_file, "w") as f:
                json.dump(session_data, f, indent=4)
        except Exception as e:
            # Don't crash the main agent flow if logging fails
            pass
            
        # --------------------------------------------

        # Output Result
        print(response_content)

    except ImportError as e:
        print(f"CRITICAL: Import Error - {str(e)}")
    except Exception as e:
        print(f"AGENT ERROR: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: cai_loader.py <agent> <prompt>")
        sys.exit(1)
        
    agent_name = sys.argv[1]
    user_prompt = " ".join(sys.argv[2:])
    
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    asyncio.run(run_agent_task(agent_name, user_prompt))