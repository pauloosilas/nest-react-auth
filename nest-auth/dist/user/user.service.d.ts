import { Repository } from 'typeorm';
import { User } from './user.entity';
export declare class UserService {
    protected readonly userRepository: Repository<User>;
    constructor(userRepository: Repository<User>);
    save(body: any): Promise<any>;
    findOne(options: any): Promise<User>;
}
