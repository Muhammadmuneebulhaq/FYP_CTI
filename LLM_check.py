from google import genai

client = genai.Client(api_key="AIzaSyDyqmYs8rPD7ar6zX8Z0HoRFZPOG4sBmEc")
chat = client.chats.create(model="gemini-2.5-flash")

# Optional: add system instruction
response = chat.send_message("You are a STIX validation expert. Validate this JSON versus the document.")
print(response.text)
