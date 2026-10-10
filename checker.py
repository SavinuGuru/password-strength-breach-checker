import re
import hashlib
import requests

def check_password_strength(password):
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
        feedback.append("Good length (12+ characters).")
    elif len(password) >= 8:
        score += 1
        feedback.append("Decent length, but 12+ characters is stronger.")
    else:
        feedback.append("Too short: use at least 8 characters, ideally 12+.")

    # Uppercase check
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    # Lowercase check
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    # Digit check
    if re.search(r'[0-9]', password):                                                                                                                                                                                                      
        score += 1                                                                                                                                                                                                                         
    else:                                                                                                                                                                                                                                  
        feedback.append("Add at least one number.")                                                                                                                                                                                        
                                                                                                                                                                                                                                           
    # Special character check                                                                                                                                                                                                              
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):                                                                                                                                                                                     
        score += 1                                                                                                                                                                                                                         
    else:                                                                                                                                                                                                                                  
        feedback.append("Add at least one special character (!@#$% etc).")                                                                                                                                                                 
                                                                                                                                                                                                                                           
    # Common password check                                                                                                                                                                                                                
    common_passwords = ['password', '123456', 'qwerty', 'letmein', 'password1', 'admin']                                                                                                                                                   
    if password.lower() in common_passwords:                                                                                                                                                                                               
        score = 0                                                                                                                                                                                                                          
        feedback = ["This is an extremely common password. Change it immediately."]                                                                                                                                                        
                                                                                                                                                                                                                                           
    return score, feedback                                                                                                                                                                                                                 

def get_strength_label(score):
    if score <= 2:
        return "Weak"
    elif score <= 4:
        return "Moderate"
    else:
        return "Strong"

def check_breach(password):
    """
    Checks the password against the Have I Been Pwned database using
    k-anonymity: only the first 5 characters of the SHA-1 hash are sent.
    Returns the number of times it appeared in breaches, or None on error.
    """
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"\nCould not reach the breach database: {e}")
        return None

    # Each line looks like: HASH_SUFFIX:COUNT
    for line in response.text.splitlines():
        hash_suffix, count = line.split(':')
        if hash_suffix == suffix:
            return int(count)
    return 0

if __name__ == '__main__':
    password = input("Enter a password to check: ")

    score, feedback = check_password_strength(password)
    label = get_strength_label(score)

    print(f"\nStrength: {label} (score: {score}/6)")
    print("Feedback:")
    for item in feedback:
        print(f"  - {item}")

    print("\nChecking known data breaches...")
    breaches = check_breach(password)

    if breaches is None:
        print("Breach check skipped.")
    elif breaches > 0:
        print(f"WARNING: This password has appeared in {breaches:,} data breaches. Do not use it.")
    else:
        print("Good news: this password was not found in any known breaches.")