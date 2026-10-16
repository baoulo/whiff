-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: harbour
-- Server version	8.0.36

/*!40101 SET NAMES utf8mb4 */;
DROP TABLE IF EXISTS `crew`;
CREATE TABLE `crew` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `rank` enum('captain','mate','deckhand') DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

LOCK TABLES `crew` WRITE;
INSERT INTO `crew` VALUES (1,'Ada Example','captain'),(2,'Ben; Sample','mate'),(3,'Cleo','deckhand');
UNLOCK TABLES;

DELIMITER ;;
CREATE PROCEDURE `crew_count`() BEGIN SELECT COUNT(*) FROM crew; END ;;
DELIMITER ;
