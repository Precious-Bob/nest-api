import { IsEmail, IsNotEmpty, IsStrongPassword } from 'class-validator';

export class signupDto {
  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @IsStrongPassword()
  password: string;

  @IsNotEmpty()
  name: string;
}
