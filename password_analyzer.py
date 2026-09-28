import re


# ============================================================
# COMMON WEAK PASSWORDS
# ============================================================

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "welcome",
    "letmein",
    "abc123"
}


# ============================================================
# REPEATED CHARACTER CHECK
# ============================================================

def contains_repeated_characters(password):
    """
    Checks whether the same character occurs
    three or more times continuously.
    """

    return bool(re.search(r"(.)\1\1", password))


# ============================================================
# SEQUENTIAL PATTERN CHECK
# ============================================================

def contains_sequential_pattern(password):
    """
    Checks for simple sequential patterns commonly
    used in weak passwords.
    """

    patterns = [
        "123",
        "234",
        "345",
        "456",
        "567",
        "678",
        "789",
        "abc",
        "bcd",
        "cde",
        "def",
        "qwe",
        "wer",
        "ert"
    ]

    password_lower = password.lower()

    for pattern in patterns:

        if pattern in password_lower:
            return True

    return False


# ============================================================
# PASSWORD ANALYZER
# ============================================================

def analyze_password(password):

    # --------------------------------------------------------
    # 1. INPUT VALIDATION
    # --------------------------------------------------------

    if not password:
        return {
            "error": "Password cannot be empty."
        }

    if password.strip() == "":
        return {
            "error": "Password cannot contain only spaces."
        }

    # --------------------------------------------------------
    # 2. REGULAR EXPRESSION CHECKS
    # --------------------------------------------------------

    has_lowercase = bool(re.search(r"[a-z]", password))
    has_uppercase = bool(re.search(r"[A-Z]", password))
    has_number = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9]", password))

    # --------------------------------------------------------
    # 3. PASSWORD LENGTH
    # --------------------------------------------------------

    length = len(password)

    # --------------------------------------------------------
    # 4. WEAK PASSWORD PATTERN CHECKS
    # --------------------------------------------------------

    is_common_password = (
        password.lower() in COMMON_PASSWORDS
    )

    has_repeated_characters = (
        contains_repeated_characters(password)
    )

    has_sequential_pattern = (
        contains_sequential_pattern(password)
    )

    # --------------------------------------------------------
    # 5. SECURITY SCORE
    # Maximum score = 100
    # --------------------------------------------------------

    score = 0

    # Length score

    if length >= 8:
        score += 20

    if length >= 12:
        score += 10

    if length >= 16:
        score += 10

    # Character complexity

    if has_lowercase:
        score += 15

    if has_uppercase:
        score += 15

    if has_number:
        score += 15

    if has_special:
        score += 15

    # --------------------------------------------------------
    # 6. PENALTY FOR WEAK PATTERNS
    # --------------------------------------------------------

    if is_common_password:
        score -= 30

    if has_repeated_characters:
        score -= 10

    if has_sequential_pattern:
        score -= 10

    # Keep score between 0 and 100

    score = max(0, min(score, 100))

    # --------------------------------------------------------
    # 7. STRENGTH LEVEL
    # --------------------------------------------------------

    if score < 40:
        strength = "Weak"

    elif score < 70:
        strength = "Medium"

    elif score < 90:
        strength = "Strong"

    else:
        strength = "Very Strong"

    # --------------------------------------------------------
    # 8. PASSWORD POLICY
    # --------------------------------------------------------

    policy = {
        "Minimum 8 characters": length >= 8,
        "Lowercase letter": has_lowercase,
        "Uppercase letter": has_uppercase,
        "Number": has_number,
        "Special character": has_special
    }

    policy_passed = all(policy.values())

    # --------------------------------------------------------
    # 9. RECOMMENDATIONS
    # --------------------------------------------------------

    recommendations = []

    if length < 8:
        recommendations.append(
            "Use at least 8 characters."
        )

    if not has_lowercase:
        recommendations.append(
            "Add at least one lowercase letter."
        )

    if not has_uppercase:
        recommendations.append(
            "Add at least one uppercase letter."
        )

    if not has_number:
        recommendations.append(
            "Add at least one number."
        )

    if not has_special:
        recommendations.append(
            "Add at least one special character."
        )

    if is_common_password:
        recommendations.append(
            "Avoid common passwords that are easy to guess."
        )

    if has_repeated_characters:
        recommendations.append(
            "Avoid repeating the same character multiple times."
        )

    if has_sequential_pattern:
        recommendations.append(
            "Avoid simple sequential patterns such as 123 or abc."
        )

    if not recommendations:
        recommendations.append(
            "No improvements required."
        )

    # --------------------------------------------------------
    # 10. RETURN RESULT
    # --------------------------------------------------------

    return {
        "length": length,
        "score": score,
        "strength": strength,

        "policy": policy,
        "policy_passed": policy_passed,

        "common_password": is_common_password,
        "repeated_characters": has_repeated_characters,
        "sequential_pattern": has_sequential_pattern,

        "recommendations": recommendations
    }


# ============================================================
# TESTING
# ============================================================

if __name__ == "__main__":

    password = input("Enter a password: ")

    result = analyze_password(password)

    print("\nPassword Analysis")
    print("-------------------------")

    if "error" in result:

        print("Error:", result["error"])

    else:

        print("Length:", result["length"])
        print("Security Score:", result["score"], "/100")
        print("Strength:", result["strength"])

        print("\nPassword Policy:")

        for rule, passed in result["policy"].items():

            if passed:
                print("[✓]", rule)

            else:
                print("[✗]", rule)

        if result["policy_passed"]:
            print("\nPolicy Status: PASSED")

        else:
            print("\nPolicy Status: NOT PASSED")

        print("\nWeak Password Checks:")

        if result["common_password"]:
            print("[!] Common password detected")

        else:
            print("[✓] Not a common password")

        if result["repeated_characters"]:
            print("[!] Repeated characters detected")

        else:
            print("[✓] No repeated character pattern")

        if result["sequential_pattern"]:
            print("[!] Sequential pattern detected")

        else:
            print("[✓] No simple sequential pattern")

        print("\nRecommendations:")

        for recommendation in result["recommendations"]:
            print("-", recommendation)