import time
from flask import redirect, render_template

def apply_deception(action):
    if action == 0:
        return None  # normal fake response
    elif action == 1:
        time.sleep(3)
    elif action == 2:
        return redirect("/fake404")
    elif action == 3:
        pass  # increase logging
    elif action == 4:
        return render_template("fake404.html")
