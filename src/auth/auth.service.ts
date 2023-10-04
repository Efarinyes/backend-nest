
import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';

import { User } from './entities/user.entity';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto, LoginDto, UpdateAuthDto, CreateUserDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {

      const { password, ...userData } = createUserDto

      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      })
      await newUser.save()

      const { password: _, ...user } = newUser.toJSON()

      return user

    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exist`)
      }
      throw new InternalServerErrorException('Something terribe hapend')
    }
  }

  // async register( registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    
  //   const user = await this.create(registerUserDto )
  //   console.log({user})
    
  //   return {
  //     user,
  //     token: this.getJwToken({ id: user._id})
  //   }
  // }  

  async register( registerDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerDto );

    return {
      user: user,
      token: this.getJwToken({ id: user._id })
    }
  }


  async login(loginDto: LoginDto): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email })
    if (!user) {
      throw new UnauthorizedException('Credencials incorrectes')
    }

    if (!bcryptjs.compareSync( password, user.password)) {
      throw new UnauthorizedException('Credencials incorrectes')
    }

    const { password: _, ...rest } = user.toJSON()

    return {
      user: rest,
      token: this.getJwToken({ id: user.id})
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById( id: string ) {
    const user = await this.userModel.findById( id )
    const { password, ...rest } = user.toJSON()
    return rest
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwToken( payload: JwtPayload ) {
    const token = this.jwtService.sign(payload);
    return token
  }
}
