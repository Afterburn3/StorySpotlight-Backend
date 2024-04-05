-- Table:
-- Books with review, Users sign up, List of Review

CREATE TABLE booksList (
    id BIGSERIAL NOT NULL PRIMARY KEY,
    book_title VARCHAR(50) NOT NULL,
    author VARCHAR(50) NOT NULL,
    book_id VARCHAR(50) NOT NULL,
    year INT NOT NULL,
    book_snippet VARCHAR NOT NULL,
    img_link VARCHAR(255) NOT NULL,
    categories VARCHAR(50) NOT NULL,
    book_description TEXT
);

CREATE TABLE users (
    user_id serial PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
);

CREATE TABLE reviews (
    id BIGSERIAL NOT NULL PRIMARY KEY,
    booksList_id BIGINT NOT NULL REFERENCES booksList(id),
    username_id BIGINT NOT NULL REFERENCES users(user_id),
    review TEXT NOT NULL,
    rating INT NOT NULL check(
        rating >= 1
        and rating <= 5
    ),
    created_at DATE DEFAULT current_date
);

SELECT Avg(rating) FROM reviews WHERE bookslist_id = 10;