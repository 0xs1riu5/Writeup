CREATE DATABASE /*!32312 IF NOT EXISTS*/ `test` /*!40100 DEFAULT CHARACTER SET utf8 */;

USE `test`;

DROP TABLE IF EXISTS user;
CREATE TABLE user(
  id INT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(100) UNIQUE ,
  password CHAR(32),
  phone VARCHAR(255)
);

INSERT INTO user(username, password, phone) VALUE ('admin',md5('shadowGam'),'flag{x4dsj-luffy-x87f-1dkj}');
