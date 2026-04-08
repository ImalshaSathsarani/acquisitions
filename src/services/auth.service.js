import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js'; 
import { eq } from 'drizzle-orm';

export const hashPassword = async (password) => {
  try{
    return await bcrypt.hash(password, 10);

  }catch(e){
    logger.error(`Error hashing the passsword: ${e}`);
    throw new Error('Error hashing', {cause: e});
  }
};

export const comparePassword = async (password, hashedPassword) => {
  try {
    return await bcrypt.compare(password, hashedPassword);
  } catch (e) {
    logger.error(`Error comparing password: ${e}`);
    throw new Error('Error comparing password', { cause: e });
  }
};

export const createUser = async ( {name, email, password, role= 'user'}) => {
  try{
    const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);
    if(existingUser.length > 0) {
      throw new Error('User with this email already exists');
    }
    const password_hash = await hashPassword(password);
    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: password_hash, role})
      .returning( { id: users.id, name: users.name, email: users.email, role: users.role, created_at: users.created_at});
    logger.info(`User created with id: ${newUser.id} ${newUser.email}`);
    return newUser; 

  }catch(e){
    // logger.error(`Error creating user: ${e}`);
    // throw new Error('Error creating user', { cause: e });
    // 1. Log the error for debugging
    logger.error(`Error in createUser service: ${e.message}`);

    // 2. If it's our specific "already exists" error, throw it directly
    if (e.message === 'User with this email already exists') {
      throw e; 
    }

    // 3. Otherwise, wrap generic DB/System errors
    throw new Error('Error creating user', { cause: e });
  }
};

export const authenticateUser = async ({ email, password }) => {
  try {
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!existingUser) {
      throw new Error('User not found');
    }

    const isPasswordValid = await comparePassword(
      password,
      existingUser.password
    );

    if (!isPasswordValid) {
      throw new Error('Invalid password');
    }

    logger.info(`User ${existingUser.email} authenticated successfully`);
    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
      created_at: existingUser.created_at,
    };
  } catch (e) {
    logger.error(`Error authenticating user: ${e}`);
    throw e;
  }
};