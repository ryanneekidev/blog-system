/*
  Warnings:

  - You are about to drop the column `Likes` on the `Post` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "Post" DROP COLUMN "Likes",
ADD COLUMN     "likes" INTEGER NOT NULL DEFAULT 0;
