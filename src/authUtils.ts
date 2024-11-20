import bcrypt from 'bcryptjs'

export async function hashPasswordAndValidate(password: string, passwordConfirm: string){
    if(password !== passwordConfirm){
        throw new Error('Passwords do not match')
    }
    const hashPassword = await bcrypt.hash(password, 12)
    return hashPassword
}