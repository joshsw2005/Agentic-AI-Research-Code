import html

def display_comment(user_input):
    escaped = html.escape(user_input)  # Safe: properly escaped
    return f"<p>{escaped}</p>"
