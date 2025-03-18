from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_register_user():
    response = client.post("/register/", params={
        "email": "user@gmail.com",
        "password": "user",
        "website": "NA"
    })
    assert response.status_code == 200
    assert response.json()["message"] == "Registration successful"

# def test_login_valid_credentials():
#     response = client.post("/token", data={"email": "user@gmail.com", "password": "testpassword"})
#     assert response.status_code == 200
#     assert response.json()["access_token"] is not None

# def test_login_invalid_credentials():
#     response = client.post("/token", data={"username": "wrong@example.com", "password": "wrongpassword"})
#     assert response.status_code == 401
#     assert response.json()["detail"] == "Incorrect email or password"

# def test_update_password():
#     login_response = client.post("/token", data={"username": "user@gmail.com", "password": "testpassword"})
#     token = login_response.json().get("access_token")
#     headers = {"Authorization": f"Bearer {token}"}
#     response = client.put("/update-password/", params={
#         "email": "user@gmail.com",
#         "new_password": "newsecurepassword"
#     }, headers=headers)
#     assert response.status_code == 200
#     assert response.json()["message"] == "Password updated successfully"

# def test_add_website_password():
#     login_response = client.post("/token", data={"username": "user@gmail.com", "password": "testpassword"})
#     token = login_response.json().get("access_token")
#     headers = {"Authorization": f"Bearer {token}"}
#     response = client.post("/add-websites-passwords/", params={
#         "website": "abc.com",
#         "hashed_password": "securepassword"
#     }, headers=headers)
#     assert response.status_code == 200
#     assert response.json()["message"] == "Website password added successfully!"

# def test_get_website_passwords():
#     login_response = client.post("/token", data={"username": "user@gmail.com", "password": "testpassword"})
#     token = login_response.json().get("access_token")
#     headers = {"Authorization": f"Bearer {token}"}
#     response = client.get("/get-websites-passwords/", headers=headers)
#     assert response.status_code == 200

# def test_delete_user():
#     login_response = client.post("/token", data={"username": "user@gmail.com", "password": "testpassword"})
#     token = login_response.json().get("access_token")
#     headers = {"Authorization": f"Bearer {token}"}
