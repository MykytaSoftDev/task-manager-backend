import {
	IsEmail,
	IsNumber,
	IsOptional,
	IsString,
	Max,
	Min,
	MinLength,
} from 'class-validator'

export class PomodoroSettingsDto {
	@IsOptional()
	@IsNumber()
	@Min(1)
	workInterval?: number

	@IsOptional()
	@IsNumber()
	@Min(1)
	breakInterval?: number

	@IsOptional()
	@IsNumber()
	@Min(1)
	@Max(10)
	intervalsCount?: number
}

export class UserDto extends PomodoroSettingsDto {
	id: string

	@IsEmail()
	@IsOptional()
	email: string

	@MinLength(8, { message: 'Password must be at least 8 characters long' })
	@IsOptional()
	@IsString()
	password: string
}
