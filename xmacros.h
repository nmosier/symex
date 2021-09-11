#pragma once

#ifndef STR
# define STR(x) #x
#endif

#ifndef XSTR
# define XSTR(x) STR(x)
#endif

#define XM_IDEN_ENT(name, ...) name

#define XM_LIST_ENT(name, ...) name,
#define XM_LIST(XM) XM(XM_LIST_ENT, XM_IDEN_ENT)

#define XM_ARRAY(XM) { XM_LIST(XM) }

#define XM_ENUM_CLASS(name, XM) enum class name XM_ARRAY(XM)



#define XM_STR_LIST_ENT_(name, ...) #name
#define XM_STR_LIST_ENT(name, ...)  #name,
#define XM_STR_LIST(XM) XM(XM_STR_LIST_ENT, XM_STR_LIST_ENT_)


#define XM_SIZE_ENT_(name, ...) 1
#define XM_SIZE_ENT(name, ...) 1 +
#define XM_SIZE(XM) (XM(XM_SIZE_ENT, XM_SIZE_ENT_))
