"""User-fetch helper.

The fetch_user function below has a docstring that doesn't match the code.
"""


def fetch_user(user_id: int) -> dict:
    """Look up a user by id and return their profile.

    Raises:
        ValueError: if user_id is not a positive integer.
        KeyError: if no user with that id exists.

    Returns:
        A dict with keys 'id', 'name', 'email', and 'created_at'.
    """
    # Actual code:
    if not isinstance(user_id, int) or user_id <= 0:
        return None
    fake_db = {
        1: {"id": 1, "name": "alice", "email": "alice@example.com"},
        2: {"id": 2, "name": "bob", "email": "bob@example.com"},
    }
    return fake_db.get(user_id)
