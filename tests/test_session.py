def test_disabled_users_session_is_dead_immediately(world):
    world.grant("viewer1@test.com", "read")
    assert world.viewer.get("/dashboard").status_code == 200
    world.set_active("viewer1@test.com", False)
    r = world.viewer.get("/dashboard")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]