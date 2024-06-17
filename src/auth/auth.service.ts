import { BadRequestException, Body, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs'
import { CreateUserDto, RegisterUserDto, LoginDto, UpdateAuthDto } from './dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name) 
    private userModel: Model<User>,
    private jwtService: JwtService,
    
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {    
    try {
    // 1- ENCRIPTAR CONTRASEÑA
      const {password, ...userData} = createUserDto
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      })

    // 2- GUARDAR USUARIO 
      await newUser.save()
      const{password:_, ...user} = newUser.toJSON();  
      return user
    // 3- GENERAR EL JWT

    } catch (error) {
      if(error.code = 1100){
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException('Something went wrong')
    }

  }

  async register(registerDto: RegisterUserDto):Promise<LoginResponse>{
    const user = await this.create(registerDto);
    console.log({user})

    return{
      user,
      token: this.getJwt({id: user._id})
    }
  }

  async login(loginDto:LoginDto): Promise<LoginResponse>{
    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email})
    if(!user){
      throw new UnauthorizedException('Not Valid Credentials - email' );
    }

    if(!bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Not Valid Credentials - password' );
    }

    const{password:_, ...rest} = user.toJSON()

    return {
      user : rest,
      token: this.getJwt({id: user.id})
    }
  }

  findAll(): Promise<User[]> {
    return this.userModel.find()
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...rest} = user.toJSON()
    return rest;
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

  getJwt(payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token
  }
}
