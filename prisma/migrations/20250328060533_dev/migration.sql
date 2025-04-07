-- CreateEnum
CREATE TYPE "Status" AS ENUM ('NORMAL', 'ADMIN');

-- AlterTable
ALTER TABLE "Post" ADD COLUMN     "postStatus" "Status" NOT NULL DEFAULT 'NORMAL';
