import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"
import { cookieOptions } from "../constants.js"

const generateAccessAndRefreshTokens = async (userId) => {
    try {
        const user = await User.findById(userId)

        const accessToken = await user.generateAccessToken()
        const refreshToken = await user.generateRefreshToken()

        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating access and refresh tokens")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for avatar
    // upload them to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res


    const { fullName, username, email, password } = req.body;

    if ([fullName, username, email, password].some((field) => field?.trim() === "")) {
        throw new ApiError(400, "All fields are required!")
    }

    const existedUser = await User.findOne({ $or: [{ username }, { email }] })

    if (existedUser) {
        throw new ApiError(409, "User with username or email already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files?.coverImage[0]?.path;
    }

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    const user = await User.create({
        fullName,
        username: username.toLowerCase(),
        email,
        avatar: avatar.secure_url,
        coverImage: coverImage?.secure_url || "",
        password,
    })

    const createdUser = await User.findById(user.id).select(
        "-password -refreshToken"
    );

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user?")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registerd successfully!")
    )

})

const loginUser = asyncHandler(async (req, res) => {
    //Get the data from the frontend
    //check the validation
    //find the user exists or not using email or else username
    //if the user is there check the password
    //if password correct generate accessToken & refreshToken
    //return the res

    const { username, email, password } = req.body;

    if (!username && !email) {
        throw new ApiError(400, "username or email is reqiured")
    }

    const user = await User.findOne({ $or: [{ username }, { email }] })

    if (!user) {
        throw new ApiError(404, "User does'nt exists")
    }

    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid user credentials")
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    //Optional Step
    const loggedInUser = await User.findById(user._id).select("-password -refreshToken");

    return res.status(200)
        .cookie("accessToken", accessToken, cookieOptions)
        .cookie("refreshToken", refreshToken, cookieOptions)
        .json(new ApiResponse(200, { user: loggedInUser, accessToken, refreshToken }, "User Logged In Successfully"))
})

const logoutUser = asyncHandler(async (req, res) => {
    //remove the cookies
    //reset the accessToken and refreshToken

    await User.findByIdAndUpdate(req.user._id,
        {
            $set: {
                refreshToken: undefined,
            }
        },
        {
            new: true
        }
    )

    return res.status(200)
        .clearCookie("accessToken", cookieOptions)
        .clearCookie("refreshToken", cookieOptions)
        .json(new ApiResponse(200, {}, "User Logged Out Successfully"))

})

const refreshAccessToken = asyncHandler(async (req, res) => {
    try {
        const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!incomingRefreshToken) {
            throw new ApiError(401, "Unauthorized Request")
        }

        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)

        const user = await User.findById(decodedToken?._id);

        if (!user) {
            throw new ApiError(401, "Invalid Refresh Token")
        }

        if (user?.refreshToken !== incomingRefreshToken) {
            throw new ApiError(401, "Refresh Token is Expired or Used")
        }

        const accessToken = await generateAccessAndRefreshTokens(user._id)
        const newRefreshToken = await generateAccessAndRefreshTokens(user._id)

        return res.status(200)
            .cookie("accessToken", accessToken, cookieOptions)
            .cookie("refreshToken", newRefreshToken, cookieOptions)
            .json(new ApiResponse(200, { accessToken, refreshToken: newRefreshToken }, "Access Token Refreshed"))
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Refresh Token")
    }
})

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword, confirmPassword } = req.body;

    if (!(newPassword === confirmPassword)) {
        throw new ApiError("Password Not Matching?");
    }

    const user = await User.findById(req.user?._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

    if (!isPasswordCorrect) {
        throw new ApiError(400, "Invalid Password!")
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false })

    return res.status(200).json(new ApiResponse(200, "Password Changed Successfully"))
})

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req.user, "Current User Fetched Successfully"))
})

const updateUserDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body;

    if (fullName || !email) {
        throw new ApiError(400, "All Fields Are Required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set: {
                fullName,
                email
            }
        },
        {
            new: true
        }).select("-password");

    return res.status(200).json(new ApiResponse(200, user, "User Details Updated Successfully"))
})

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar File Is Missing")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);

    if (!avatar) {
        throw new ApiError(400, "Error While Uploading On Avatar")
    }

    const user = await User.findByIdAndDelete(
        req?.user._id,
        {
            $set: {
                avatar: avatar.secure_url
            }
        },
        {
            new: true
        }).select("-password")

    return res.status(200).json(new ApiResponse(200, user, "Avatar Updated Successfully"))
})

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover Image File Is Missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!coverImage) {
        throw new ApiError(400, "Error While Uploading On Cover Image")
    }

    const user = await User.findByIdAndDelete(
        req?.user._id,
        {
            $set: {
                coverImage: coverImage.secure_url
            }
        },
        {
            new: true
        }).select("-password")

    return res.status(200).json(new ApiResponse(200, user, "Cover Image Updated Successfully"))
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateUserDetails,
    updateUserAvatar,
    updateUserCoverImage
}